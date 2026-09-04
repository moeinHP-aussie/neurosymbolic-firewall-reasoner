"""Local web interface for Phase 4 firewall-policy reports."""

from __future__ import annotations

import os
import secrets
import time
from collections import Counter

# Load variables from a local .env file (e.g. GEMINI_API_KEY=...) into the
# process environment before anything below reads os.environ. This is a
# convenience only: python-dotenv is optional (same soft-dependency pattern
# as nl_query below) so the app still starts if it isn't installed --
# operators can always export the real environment variable instead of
# using a .env file. load_dotenv() is a no-op if no .env file is present,
# and never overwrites a variable that is already set in the environment
# (e.g. one exported by the shell or a process manager), so an explicit
# `export GEMINI_API_KEY=...` always wins over the .env file.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, Response, render_template, request

from bridge import Finding, backend_name, run_engine
from incremental import check_new_rules
from parser import ParseError, parse
import audit_log
# Natural-language querying is an optional dependency.  Keeping the import
# soft means the established audit UI still starts before an operator installs
# the extra Gemini/Pydantic packages listed in requirements.txt.
try:
    from nl_query.nl_translator import (
        NLTranslator,
        TranslatorConfigurationError,
        TranslatorAllKeysFailedError,
        dispatch,
    )
except ImportError:
    NLTranslator = None
    TranslatorConfigurationError = None
    TranslatorAllKeysFailedError = None
    dispatch = None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# ── minimal access control ──────────────────────────────────────────
# This app reads firewall topology (IPs, ports, allow/deny structure)
# uploaded by whoever can reach it -- that's sensitive enough that an
# unauthenticated, network-reachable instance is not acceptable for
# real IT-center use, even though the analysis itself is read-only and
# makes no changes to the actual firewall.
#
# Deliberately kept to single-shared-password HTTP Basic Auth rather
# than a full user/session/database system: this app has no per-user
# state or roles to justify that complexity yet (see README's Known
# Limitations for what a real multi-user login would need). Basic Auth
# over plain HTTP still sends the password in a trivially-decodable
# (base64, not encrypted) form on every request -- it is NOT a
# substitute for running this behind HTTPS/a reverse proxy if it is
# ever exposed beyond localhost/a trusted LAN.
#
# Auth is OFF (open access) unless FIREWALLLOGIC_PASSWORD is set in
# the environment, so the zero-setup local/demo workflow
# (`python3 webapp.py` with no configuration) keeps working exactly as
# before for anyone who hasn't opted in.
_AUTH_PASSWORD = os.environ.get("FIREWALLLOGIC_PASSWORD")
_AUTH_USERNAME = os.environ.get("FIREWALLLOGIC_USERNAME", "admin")


def _check_auth(username: str, password: str) -> bool:
    # secrets.compare_digest instead of == to avoid a timing side
    # channel leaking how many leading characters of the password guess
    # were correct.
    return (
        secrets.compare_digest(username, _AUTH_USERNAME)
        and secrets.compare_digest(password, _AUTH_PASSWORD)
    )


@app.before_request
def _require_auth():
    if _AUTH_PASSWORD is None:
        return None  # auth not configured — open access, as before
    auth = request.authorization
    if not auth or not _check_auth(auth.username or "", auth.password or ""):
        lang = _resolve_lang()
        message = (
            "دسترسی نیازمند احراز هویت است."
            if lang == "fa"
            else "Authentication is required."
        )
        return Response(
            message,
            401,
            {"WWW-Authenticate": 'Basic realm="FirewallLogic"'},
        )
    return None


SEVERITY_ORDER = ("critical", "high", "medium", "low")

# ── bilingual content ───────────────────────────────────────────────
# Every user-facing string that lives in Python (as opposed to inside
# firewall_engine.pl's Explanation text, which bridge.py/webapp.py
# receive already rendered in the right language via lang=...) is
# keyed here by language so a single _t()/_labels_for() lookup covers
# both. fa stays first / default in every dict so behavior for anyone
# who never touches the language switch is byte-for-byte unchanged
# from before this feature existed.
SUPPORTED_LANGS = ("fa", "en")
DEFAULT_LANG = "en"

SEVERITY_LABELS = {
    "fa": {"critical": "بحرانی", "high": "شدید", "medium": "متوسط", "low": "کم"},
    "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
}
TYPE_LABELS = {
    "fa": {
        "shadowing": "سایه‌خوردگی",
        "redundancy": "افزونگی",
        "correlation": "تداخل / تعارض",
        "generalization": "تعمیم",
    },
    "en": {
        "shadowing": "Shadowing",
        "redundancy": "Redundancy",
        "correlation": "Correlation",
        "generalization": "Generalization",
    },
}
RECOMMENDATIONS = {
    "fa": {
        "shadowing": "قانون ثانویه هرگز اجرا نمی‌شود؛ ترتیب دو قانون را بازبینی کنید یا قانون غیرقابل‌دسترسی را حذف کنید.",
        "redundancy": "قانون افزونه تصمیمی را تغییر نمی‌دهد؛ پس از تأیید مسئول شبکه، حذف یا ادغام آن را بررسی کنید.",
        "correlation": "دو قانون روی بخشی از ترافیک نتیجهٔ متضاد دارند؛ ترتیب و هدف امنیتی آن‌ها باید دستی تأیید شود.",
        "generalization": "ممکن است این ترتیب عمدی باشد؛ آن را مستند کنید تا در تغییرات بعدی جابه‌جا نشود.",
    },
    "en": {
        "shadowing": "The secondary rule never executes; review the order of the two rules or remove the unreachable one.",
        "redundancy": "The redundant rule never changes the decision; after confirming with the network owner, consider removing or merging it.",
        "correlation": "The two rules disagree on part of their shared traffic; their order and security intent should be verified manually.",
        "generalization": "This ordering may be intentional; document it so it isn't accidentally reordered in future changes.",
    },
}

# Static template strings (index/report/check_new pages). Kept here
# rather than duplicated as separate .html files per language, so a
# copy-edit only ever needs to happen in one place per string, and the
# fa/en versions can't silently drift out of structural sync with each
# other (same keys always exist in both, checked by _t() below).
UI_TEXT = {
    "fa": {
        "dir": "rtl",
        "html_lang": "fa",
        "app_title": "FirewallLogic — تحلیل‌گر قوانین فایروال",
        "lang_switch_label": "زبان گزارش",
        "lang_name_fa": "فارسی",
        "lang_name_en": "English",
        "nav_full_check": "بررسی کامل",
        "nav_incremental": "بررسی افزایشی",
        "nav_nl_query": "پرسش از قوانین",
        "upload_label": "فایل پیکربندی فایروال",
        "upload_hint": "iptables-save یا nftables — حداکثر ۵ مگابایت",
        "strict_label": "حالت سخت‌گیرانه (توقف در صورت وجود خط غیرقابل‌تجزیه)",
        "submit_analyze": "تحلیل کن",
        "error_no_file": "یک فایل پیکربندی انتخاب کنید.",
        "error_bad_encoding": "فایل باید با UTF-8 ذخیره شده باشد تا تحلیل بدون ابهام انجام شود.",
        "error_no_rules": "هیچ قانون پشتیبانی‌شده‌ای در فایل پیدا نشد.",
        "error_file_too_large": "حجم فایل باید حداکثر ۵ مگابایت باشد.",
        "error_engine_prefix": "خطای موتور تحلیل: ",
        "error_both_files_required": "هر دو فایل (پیکربندی فعلی و قوانین پیشنهادی) الزامی هستند.",
        "error_bad_encoding_both": "هر دو فایل باید با UTF-8 ذخیره شده باشند.",
        "error_no_rules_either": "هیچ قانون پشتیبانی‌شده‌ای در هیچ‌کدام از دو فایل پیدا نشد.",
        "error_no_new_rules": "هیچ قانون پشتیبانی‌شده‌ای در فایل «قوانین پیشنهادی» پیدا نشد — فقط قوانینی که می‌خواهید اضافه کنید را در آن فایل قرار دهید.",
        "base_config_label": "پیکربندی فعلی",
        "new_rules_label": "قوانین پیشنهادی",
        "submit_check_new": "بررسی کن",
        "report_title": "گزارش تحلیل",
        "source_label": "منبع",
        "rules_count_label": "تعداد قوانین",
        "findings_count_label": "تعداد یافته‌ها",
        "no_findings": "هیچ ناهنجاری‌ای یافت نشد.",
        "recommendation_label": "پیشنهاد",
        "back_link": "بازگشت",
        "page_title_index": "ممیزی قوانین فایروال · FirewallLogic",
        "masthead_h1": "گزارش قابل‌اعتماد برای قوانین فایروال",
        "masthead_lead": "فایل پیکربندی را فقط در همین رایانه تحلیل کنید — هیچ فایلی ذخیره یا به جای دیگری ارسال نمی‌شود.",
        "upload_title": "تحلیل یک فایل پیکربندی",
        "upload_field_label": "فایل iptables-save یا nftables",
        "strict_checkbox_label": "حالت دقیق: در صورت وجود قانون پشتیبانی‌نشده، گزارش نهایی صادر نشود.",
        "submit_start": "شروع تحلیل",
        "form_note": "محدودیت حجم فایل: ۵ مگابایت · فرمت فایل باید UTF-8 باشد",
        "submitting_label": "در حال تحلیل...",
        "scope_title": "دامنهٔ فعلی تحلیل",
        "scope_body": "قوانین Allow/Deny را بر اساس IP، پورت، پروتکل و chain بررسی می‌کند و چهار آنومالی اصلی — سایه‌خوردگی، افزونگی، تداخل و تعمیم — را تشخیص می‌دهد.",
        "check_new_title": "افزودن قوانین جدید به یک پیکربندی موجود؟",
        "check_new_body_pre": "اگر فقط می‌خواهید بدانید چند قانون جدید با پیکربندی فعلی یا با یکدیگر تداخل دارند — بدون بازبینی مجدد قوانین قبلی — از ",
        "check_new_body_link": "حالت بررسی قوانین جدید",
        "check_new_body_post": " استفاده کنید.",
        "page_title_report": "نتیجهٔ ممیزی فایروال · FirewallLogic",
        "back_to_new_analysis": "بازگشت به تحلیل جدید",
        "report_eyebrow": "گزارش ممیزی",
        "report_h1": "نتیجهٔ تحلیل سیاست فایروال",
        "strict_blocked_title": "تحلیل در حالت دقیق متوقف شد",
        "strict_blocked_body": "برخی قوانین مدل نشده‌اند؛ برای جلوگیری از گزارش ناقص، هیچ نتیجه‌ای صادر نشد.",
        "incomplete_title": "تحلیل ناقص است",
        "incomplete_body": "یافته‌ها فقط برای قوانین پشتیبانی‌شده معتبرند. قبل از هر تصمیم عملیاتی، خطوط ردشده را بررسی کنید.",
        "complete_message": "تحلیل کامل شد.",
        "complete_body": "همهٔ خطوط قابل‌تحلیل بودند.",
        "metrics_label": "خلاصهٔ گزارش",
        "metric_analyzed_rules": "قوانین تحلیل‌شده",
        "metric_unsupported_lines": "خطوط پشتیبانی‌نشده",
        "metric_findings": "یافته‌ها",
        "metric_analysis_time": "زمان تحلیل",
        "severity_grid_label": "یافته‌ها بر اساس شدت",
        "unsupported_lines_title": "خطوط پشتیبانی‌نشده",
        "line_word": "خط",
        "findings_title": "یافته‌های نیازمند بازبینی",
        "rule_and_rule": "قانون {a} و قانون {b}",
        "empty_state_title": "هیچ آنومالی‌ای کشف نشد",
        "empty_state_body": "قوانین تحلیل‌شده در این مدل با یکدیگر تعارضی ندارند.",
        "page_title_check_new": "بررسی قوانین جدید فایروال · FirewallLogic",
        "back_to_full_analysis": "بازگشت به تحلیل کامل",
        "incremental_eyebrow": "بررسی افزایشی",
        "check_new_h1": "آیا قوانین جدید پیشنهادی مشکلی ایجاد می‌کنند؟",
        "check_new_lead": "پیکربندی فعلی (که قبلاً بررسی و تأیید شده) را همراه با فایلی که فقط شامل قوانین جدید پیشنهادی است بارگذاری کنید. فقط یافته‌هایی که به قوانین جدید مربوط‌اند نمایش داده می‌شود.",
        "check_new_upload_title": "بررسی قوانین جدید",
        "base_config_field_label": "۱. پیکربندی فعلی (قوانین موجود و تأییدشده)",
        "new_rules_field_label": "۲. فقط قوانین جدید پیشنهادی (همان فرمت: iptables-save یا nftables)",
        "submit_check_new_button": "بررسی قوانین جدید",
        "check_new_form_note": "محدودیت حجم هر فایل: ۵ مگابایت · فرمت هر دو فایل باید UTF-8 باشد",
        "check_new_form_note2": "شمارهٔ قوانین در فایل دوم نادیده گرفته می‌شود و به‌صورت خودکار پس از آخرین قانون فایل اول شماره‌گذاری می‌شوند.",
        "check_new_scope_title": "این حالت چه تفاوتی با تحلیل کامل دارد؟",
        "check_new_scope_body": "تحلیل کامل همهٔ جفت‌قوانین را از نو بررسی می‌کند. این حالت فرض می‌کند پیکربندی فعلی قبلاً بررسی و پذیرفته شده است، و فقط نشان می‌دهد قوانین جدید با قوانین موجود یا با یکدیگر چه تداخلی دارند — مناسب برای بررسی سریع قبل از اعمال یک تغییر کوچک روی یک پیکربندی بزرگ.",
        "checking_label": "در حال بررسی...",
        "page_title_check_new_report": "نتیجهٔ بررسی قوانین جدید · FirewallLogic",
        "check_new_report_h1": "نتیجهٔ بررسی قوانین جدید",
        "metric_base_rules": "قوانین پیکربندی فعلی",
        "metric_new_rules": "قوانین جدید بررسی‌شده",
        "new_rule_ids_label": "شمارهٔ قوانین جدید",
        "base_errors_title": "خطوط پشتیبانی‌نشده در پیکربندی فعلی",
        "new_errors_title": "خطوط پشتیبانی‌نشده در قوانین جدید",
        "no_new_findings_title": "قوانین جدید مشکلی ایجاد نکردند",
        "no_new_findings_body": "قوانین جدید پیشنهادی با پیکربندی فعلی یا با یکدیگر تداخلی ندارند.",
        "check_another_link": "بررسی قوانین جدید دیگر",
        "new_rules_summary": "{base} قانون موجود · {new} قانون جدید پیشنهادی (شماره‌های {first} تا {last})",
        "incomplete_check_title": "بررسی ناقص است",
        "incomplete_check_body": "برخی خطوط در یکی از دو فایل پشتیبانی نشدند. یافته‌ها فقط برای قوانین پشتیبانی‌شده معتبرند.",
        "check_complete_message": "بررسی کامل شد.",
        "check_complete_body": "همهٔ خطوط هر دو فایل قابل‌تحلیل بودند.",
        "check_metrics_label": "خلاصهٔ بررسی",
        "metric_existing_rules": "قوانین موجود",
        "metric_new_rules_short": "قوانین جدید",
        "metric_new_findings": "یافته‌های مرتبط با قوانین جدید",
        "new_findings_note": "فقط یافته‌هایی نشان داده شده‌اند که دست‌کم یکی از دو طرفشان یکی از قوانین جدید (شماره‌های {first} تا {last}) باشد.",
        "page_title_query": "پرسش از قوانین فایروال · FirewallLogic",
        "query_eyebrow": "پرسش زبان طبیعی",
        "query_h1": "از پیکربندی فایروال سؤال بپرسید",
        "query_lead": "سؤال را فارسی یا انگلیسی بنویسید و همان فایل پیکربندی را بارگذاری کنید. پاسخ فقط با استدلال روی قوانین واقعی فایل تولید می‌شود.",
        "query_panel_title": "سؤال و پیکربندی",
        "query_question_label": "سؤال شما",
        "query_question_placeholder": "مثال: آیا 10.10.25.5 می‌تواند از طریق SSH به 192.168.50.10 وصل شود؟",
        "query_file_label": "فایل iptables-save یا nftables",
        "query_submit": "پاسخ را بررسی کن",
        "query_submitting": "در حال تحلیل سؤال...",
        "query_form_note": "فایل فقط برای همین درخواست در حافظه پردازش می‌شود و ذخیره نمی‌شود. حداکثر حجم: ۵ مگابایت.",
        "query_examples_title": "سؤال‌های نمونه",
        "query_examples_body": "می‌توانید دربارهٔ مجازبودن یک اتصال مشخص، مقصدهای قابل‌دسترسی از یک IP، منابع مجاز برای یک مقصد، قوانین مرتبط با یک IP، یا وضعیت یک قانون خاص (سایه‌خوردگی، زائد بودن، تعارض) و آمار کلی قوانین سؤال کنید. روی هرکدام از نمونه‌های زیر بزنید تا در فرم قرار بگیرد:",
        "query_examples_use": "استفاده از این سؤال",
        "query_error_no_question": "یک سؤال وارد کنید.",
        "query_error_question_too_long": "سؤال باید حداکثر ۲۰۰۰ نویسه باشد.",
        "query_error_no_file": "یک فایل پیکربندی انتخاب کنید.",
        "query_error_bad_encoding": "فایل باید با UTF-8 ذخیره شده باشد.",
        "query_error_no_rules": "هیچ قانون پشتیبانی‌شده‌ای در فایل پیدا نشد.",
        "query_error_prefix": "امکان پاسخ‌گویی به سؤال وجود ندارد: ",
        "query_error_gemini": "Gemini پیکربندی نشده است. متغیر محیطی GEMINI_API_KEY را تنظیم کنید.",
        "query_error_service": "سرویس ترجمه یا موتور استدلال با خطا روبه‌رو شد. کلید API، مدل و اتصال را بررسی کرده و دوباره تلاش کنید.",
        "query_back": "بازگشت به پرسش جدید",
        "query_result_eyebrow": "نتیجهٔ پرسش",
        "query_result_h1": "پاسخ مبتنی بر قوانین واقعی",
        "query_understood_title": "سیستم سؤال را این‌گونه فهمید",
        "query_answer_title": "پاسخ موتور استدلال",
        "query_rules_count": "قوانین قابل‌تحلیل",
        "query_parse_warning": "برخی خطوط فایل پشتیبانی نشدند؛ پاسخ فقط بر پایهٔ قوانین قابل‌تحلیل است.",
        "query_decision_allow": "مجاز (allow)",
        "query_decision_deny": "غیرمجاز (deny)",
        "query_decision_default_deny": "غیرمجاز به‌صورت پیش‌فرض (default deny)",
        "query_list_empty": "هیچ قانون Allow منطبقی یافت نشد.",
        "query_broad_limit": "نکته: این فهرست قوانین Allow منطبق را نشان می‌دهد و برای هر مقصد، تقدم denyهای با اولویت بالاتر را شبیه‌سازی نمی‌کند. برای نتیجهٔ قطعی یک اتصال مشخص، سؤال مقصد، پروتکل و پورت را کامل بنویسید.",
        "query_shadowed_yes": "بله، این قانون سایه‌خورده و هیچ‌وقت اجرا نمی‌شود، چون قانون(های) زیر زودتر و با اولویت بالاتر همان ترافیک را با اقدام متفاوت پوشش می‌دهند:",
        "query_shadowed_no": "خیر، این قانون سایه‌خورده نیست؛ قانون دیگری آن را قبل از اجرا مسدود نمی‌کند.",
        "query_redundant_yes": "بله، این قانون زائد است، چون قانون(های) زیر از قبل با همان اقدام این ترافیک را پوشش می‌دهند:",
        "query_redundant_no": "خیر، این قانون زائد نیست.",
        "query_conflict_yes": "بله، این قانون با قانون(های) زیر تعارض دارد (پوشش هم‌پوشان با اقدام متضاد):",
        "query_conflict_no": "خیر، تعارضی با قانون دیگری برای این قانون شناسایی نشد.",
        "query_rule_ref": "قانون شماره",
        "query_summary_total": "تعداد کل قوانین",
        "query_summary_allow": "قوانین Allow",
        "query_summary_deny": "قوانین Deny",
        "query_summary_by_protocol": "تفکیک بر اساس پروتکل",
    },
    "en": {
        "back_link": "Back",
        "page_title_index": "Firewall Rule Audit · FirewallLogic",
        "masthead_h1": "A trustworthy report for your firewall rules",
        "masthead_lead": "The configuration file is analyzed only on this machine — nothing is stored or sent anywhere else.",
        "upload_title": "Analyze a configuration file",
        "upload_field_label": "iptables-save or nftables file",
        "strict_checkbox_label": "Strict mode: don't produce a final report if any rule is unsupported.",
        "submit_start": "Start analysis",
        "form_note": "File size limit: 5 MB · file must be UTF-8",
        "submitting_label": "Analyzing...",
        "scope_title": "Current analysis scope",
        "scope_body": "Checks Allow/Deny rules by IP, port, protocol, and chain, and detects four core anomalies — shadowing, redundancy, correlation, and generalization.",
        "check_new_title": "Adding new rules to an existing configuration?",
        "check_new_body_pre": "If you just want to know whether some new rules conflict with the current configuration or with each other — without re-reviewing the existing rules — use ",
        "check_new_body_link": "incremental rule check mode",
        "check_new_body_post": ".",
        "dir": "ltr",
        "html_lang": "en",
        "app_title": "FirewallLogic — Firewall Rule Analyzer",
        "lang_switch_label": "Report language",
        "lang_name_fa": "فارسی",
        "lang_name_en": "English",
        "nav_full_check": "Full check",
        "nav_incremental": "Incremental check",
        "nav_nl_query": "Ask about rules",
        "upload_label": "Firewall configuration file",
        "upload_hint": "iptables-save or nftables — 5 MB max",
        "strict_label": "Strict mode (stop if any line can't be parsed)",
        "submit_analyze": "Analyze",
        "error_no_file": "Please select a configuration file.",
        "error_bad_encoding": "The file must be saved as UTF-8 for unambiguous analysis.",
        "error_no_rules": "No supported rules were found in the file.",
        "error_file_too_large": "The file must be 5 MB or smaller.",
        "error_engine_prefix": "Analysis engine error: ",
        "error_both_files_required": "Both files (current configuration and proposed rules) are required.",
        "error_bad_encoding_both": "Both files must be saved as UTF-8.",
        "error_no_rules_either": "No supported rules were found in either file.",
        "error_no_new_rules": "No supported rules were found in the \"proposed rules\" file — only put the rules you want to add in that file.",
        "base_config_label": "Current configuration",
        "new_rules_label": "Proposed rules",
        "submit_check_new": "Check",
        "report_title": "Analysis report",
        "source_label": "Source",
        "rules_count_label": "Rule count",
        "findings_count_label": "Findings",
        "no_findings": "No anomalies found.",
        "recommendation_label": "Recommendation",
        "page_title_report": "Firewall Audit Result · FirewallLogic",
        "back_to_new_analysis": "Back to a new analysis",
        "report_eyebrow": "Audit report",
        "report_h1": "Firewall policy analysis result",
        "strict_blocked_title": "Analysis stopped in strict mode",
        "strict_blocked_body": "Some rules could not be modeled; to avoid an incomplete report, no results were produced.",
        "incomplete_title": "Analysis is incomplete",
        "incomplete_body": "Findings are only valid for the supported rules. Review the skipped lines before making any operational decision.",
        "complete_message": "Analysis complete.",
        "complete_body": "Every line could be analyzed.",
        "metrics_label": "Report summary",
        "metric_analyzed_rules": "Rules analyzed",
        "metric_unsupported_lines": "Unsupported lines",
        "metric_findings": "Findings",
        "metric_analysis_time": "Analysis time",
        "severity_grid_label": "Findings by severity",
        "unsupported_lines_title": "Unsupported lines",
        "line_word": "Line",
        "findings_title": "Findings that need review",
        "rule_and_rule": "Rule {a} and rule {b}",
        "empty_state_title": "No anomalies found",
        "empty_state_body": "The analyzed rules in this model do not conflict with each other.",
        "page_title_check_new": "Check New Firewall Rules · FirewallLogic",
        "back_to_full_analysis": "Back to full analysis",
        "incremental_eyebrow": "Incremental check",
        "check_new_h1": "Do the proposed new rules cause a problem?",
        "check_new_lead": "Upload the current configuration (already reviewed and approved) together with a file containing only the proposed new rules. Only findings involving the new rules are shown.",
        "check_new_upload_title": "Check new rules",
        "base_config_field_label": "1. Current configuration (existing, approved rules)",
        "new_rules_field_label": "2. Only the proposed new rules (same format: iptables-save or nftables)",
        "submit_check_new_button": "Check new rules",
        "check_new_form_note": "File size limit per file: 5 MB · both files must be UTF-8",
        "check_new_form_note2": "Rule numbers in the second file are ignored and automatically renumbered after the last rule of the first file.",
        "check_new_scope_title": "How is this different from a full analysis?",
        "check_new_scope_body": "A full analysis re-checks every pair of rules from scratch. This mode assumes the current configuration has already been reviewed and accepted, and only shows how the new rules conflict with existing rules or with each other — useful for a quick check before applying a small change to a large configuration.",
        "checking_label": "Checking...",
        "page_title_check_new_report": "New Rules Check Result · FirewallLogic",
        "check_new_report_h1": "New rules check result",
        "metric_base_rules": "Current configuration rules",
        "metric_new_rules": "New rules checked",
        "new_rule_ids_label": "New rule numbers",
        "base_errors_title": "Unsupported lines in the current configuration",
        "new_errors_title": "Unsupported lines in the new rules",
        "no_new_findings_title": "The new rules caused no problems",
        "no_new_findings_body": "The proposed new rules do not conflict with the current configuration or with each other.",
        "check_another_link": "Check other new rules",
        "new_rules_summary": "{base} existing rule(s) · {new} proposed new rule(s) (numbers {first} to {last})",
        "incomplete_check_title": "Check is incomplete",
        "incomplete_check_body": "Some lines in one of the two files were unsupported. Findings are only valid for the supported rules.",
        "check_complete_message": "Check complete.",
        "check_complete_body": "Every line in both files could be analyzed.",
        "check_metrics_label": "Check summary",
        "metric_existing_rules": "Existing rules",
        "metric_new_rules_short": "New rules",
        "metric_new_findings": "Findings involving new rules",
        "new_findings_note": "Only findings where at least one side is one of the new rules (numbers {first} to {last}) are shown.",
        "page_title_query": "Ask Firewall Rules · FirewallLogic",
        "query_eyebrow": "Natural-language query",
        "query_h1": "Ask your firewall configuration",
        "query_lead": "Write your question in English or Persian and upload the configuration file. The answer is derived only by reasoning over that file's real rules.",
        "query_panel_title": "Question and configuration",
        "query_question_label": "Your question",
        "query_question_placeholder": "Example: Can 10.10.25.5 reach 192.168.50.10 over SSH?",
        "query_file_label": "iptables-save or nftables file",
        "query_submit": "Check the answer",
        "query_submitting": "Analyzing question...",
        "query_form_note": "The file is processed in memory only for this request and is not stored. Maximum size: 5 MB.",
        "query_examples_title": "Questions you can ask",
        "query_examples_body": "Ask whether one connection is allowed, which destinations a source can reach, which sources can reach a destination, which rules mention an IP, or about a specific rule's status (shadowed, redundant, conflicting) and overall rule statistics. Click any example below to load it into the form:",
        "query_examples_use": "Use this question",
        "query_error_no_question": "Enter a question.",
        "query_error_question_too_long": "The question must be 2,000 characters or fewer.",
        "query_error_no_file": "Select a configuration file.",
        "query_error_bad_encoding": "The file must be saved as UTF-8.",
        "query_error_no_rules": "No supported rules were found in the file.",
        "query_error_prefix": "The question could not be answered: ",
        "query_error_gemini": "Gemini is not configured. Set the GEMINI_API_KEY environment variable.",
        "query_error_service": "The translation service or reasoning engine failed. Check the API key, model, and connection, then try again.",
        "query_back": "Ask another question",
        "query_result_eyebrow": "Query result",
        "query_result_h1": "Answer based on real rules",
        "query_understood_title": "The system understood your question as",
        "query_answer_title": "Reasoning engine answer",
        "query_rules_count": "Rules analyzed",
        "query_parse_warning": "Some lines were unsupported; the answer is based only on the rules that could be analyzed.",
        "query_decision_allow": "Allowed (allow)",
        "query_decision_deny": "Denied (deny)",
        "query_decision_default_deny": "Denied by default (default deny)",
        "query_list_empty": "No matching Allow rules were found.",
        "query_broad_limit": "Note: this lists matching Allow rules and does not simulate earlier higher-priority deny rules for every destination. For a definitive answer, ask about one destination, protocol, and port.",
        "query_shadowed_yes": "Yes, this rule is shadowed and never fires, because the following earlier, higher-priority rule(s) already cover the same traffic with a different action:",
        "query_shadowed_no": "No, this rule is not shadowed; no earlier rule blocks it from running.",
        "query_redundant_yes": "Yes, this rule is redundant, because the following earlier rule(s) already cover this traffic with the same action:",
        "query_redundant_no": "No, this rule is not redundant.",
        "query_conflict_yes": "Yes, this rule conflicts with the following rule(s) (overlapping traffic, opposite actions):",
        "query_conflict_no": "No conflict was detected for this rule.",
        "query_rule_ref": "Rule",
        "query_summary_total": "Total rules",
        "query_summary_allow": "Allow rules",
        "query_summary_deny": "Deny rules",
        "query_summary_by_protocol": "Breakdown by protocol",
    },
}


def _resolve_lang() -> str:
    """
    Determines the language for this request, in priority order:
      1. ?lang=xx query param or lang form field (explicit switch,
         e.g. the language selector submitting a GET/POST) -- also
         persisted to a cookie so it "sticks" for later requests.
      2. firewalllogic_lang cookie (from a previous switch).
      3. DEFAULT_LANG ("en"), i.e. what a fresh visitor with no cookie
         and no ?lang= sees on their first request.
    Only "fa"/"en" are ever accepted; anything else silently falls
    back to the default rather than erroring, since a language switch
    should never be able to break analysis.
    """
    requested = request.values.get("lang")
    if requested in SUPPORTED_LANGS:
        return requested
    cookie_lang = request.cookies.get("firewalllogic_lang")
    if cookie_lang in SUPPORTED_LANGS:
        return cookie_lang
    return DEFAULT_LANG


def _t(lang: str) -> dict[str, str]:
    """Static UI text dict for lang, always falling back to fa."""
    return UI_TEXT.get(lang, UI_TEXT[DEFAULT_LANG])


def _finding_view(finding: Finding, lang: str) -> dict[str, str | int]:
    return {
        "type": TYPE_LABELS[lang][finding.type],
        "severity": SEVERITY_LABELS[lang][finding.severity],
        "severity_key": finding.severity,
        "primary_rule": finding.primary_id,
        "secondary_rule": finding.secondary_id,
        "explanation": finding.explanation,
        "recommendation": RECOMMENDATIONS[lang][finding.type],
    }


def _format_duration(seconds: float, lang: str) -> str:
    """
    Human-friendly rendering of an analysis duration.
    - Under 1 second: shown in milliseconds (no decimals) since fractional
      seconds like "0.03s" are harder to read at a glance than "34 ms",
      and most configs in this project's own benchmarks (see README/
      run_tests.py) finish well under a second.
    - 1 second and above: shown in seconds with 2 decimals, e.g. "1.42s" /
      "۱٫۴۲ ثانیه" -- matches the unit used in the project's own sweep-line
      benchmark writeup (13.8s / 0.45s), so this is consistent with numbers
      already documented elsewhere in the project.
    """
    ms = seconds * 1000
    if ms < 1000:
        value = f"{ms:.0f}"
        return f"{value} میلی‌ثانیه" if lang == "fa" else f"{value} ms"
    value = f"{seconds:.2f}"
    return f"{value} ثانیه" if lang == "fa" else f"{value}s"


def _report_context(
    source_name: str,
    rules_count: int,
    errors: list[ParseError],
    findings: list[Finding],
    strict: bool,
    lang: str,
    strict_blocked: bool = False,
    analysis_duration_seconds: float | None = None,
) -> dict:
    counts = Counter(finding.severity for finding in findings)
    context = {
        "source_name": source_name,
        "rules_count": rules_count,
        "errors": errors,
        "findings": [_finding_view(finding, lang) for finding in findings],
        "findings_count": len(findings),
        "severity_cards": [
            {"key": key, "label": SEVERITY_LABELS[lang][key], "count": counts[key]}
            for key in SEVERITY_ORDER
        ],
        "analysis_complete": not errors,
        "strict": strict,
        "strict_blocked": strict_blocked,
        "analysis_duration": (
            _format_duration(analysis_duration_seconds, lang)
            if analysis_duration_seconds is not None
            else None
        ),
    }
    context.update(_t(lang))
    context["lang"] = lang
    return context


QUERY_FUNCTION_LABELS = {
    "fa": {
        "is_allowed": "بررسی مجازبودن یک اتصال",
        "reachable_from": "مقصدهای قابل‌دسترسی از یک مبدأ",
        "who_can_reach": "مبدأهای مجاز برای یک مقصد",
        "rules_matching_ip": "قوانین مرتبط با یک IP",
        "why_shadowed": "علت غیرفعال‌بودن یک قانون",
        "is_redundant_rule": "بررسی زائد بودن یک قانون",
        "conflicting_rules": "قوانین در تعارض با یک قانون",
        "rule_summary": "خلاصه‌ی آماری قوانین",
    },
    "en": {
        "is_allowed": "Check one connection",
        "reachable_from": "Destinations reachable from a source",
        "who_can_reach": "Sources allowed to a destination",
        "rules_matching_ip": "Rules matching an IP",
        "why_shadowed": "Why a rule never fires",
        "is_redundant_rule": "Whether a rule is redundant",
        "conflicting_rules": "Rules conflicting with a rule",
        "rule_summary": "Rule statistics summary",
    },
}

QUERY_ARGUMENT_LABELS = {
    "fa": {
        "chain": "زنجیره", "src_ip": "IP مبدأ", "dst_ip": "IP مقصد",
        "protocol": "پروتکل", "port": "پورت مقصد", "ip": "IP",
        "direction": "جهت بررسی", "rule_id": "شماره قانون",
    },
    "en": {
        "chain": "Chain", "src_ip": "Source IP", "dst_ip": "Destination IP",
        "protocol": "Protocol", "port": "Destination port", "ip": "IP",
        "direction": "Match direction", "rule_id": "Rule number",
    },
}

# Example questions shown on the query form so users have a starting point
# for what they can ask and how to phrase it, in both supported languages.
# Kept as (Persian, English) pairs so each entry can be shown in whichever
# language the page is currently rendered in -- see _query_form_context().
# These are illustrative only (no IP/rule number here is guaranteed to
# exist in any given config); the phrasing patterns are what matters.
QUERY_EXAMPLES = {
    "fa": [
        "آیا 10.10.25.5 می‌تواند روی پورت 22 به 192.168.50.10 وصل شود؟",
        "آیا سرور 10.0.0.5 به HTTPS سرور 172.16.0.10 دسترسی دارد؟",
        "10.20.30.40 به چه مقصدهایی دسترسی دارد؟",
        "چه کسانی می‌توانند به 192.168.1.100 وصل شوند؟",
        "کدام قوانین مربوط به IP 10.10.10.10 هستند؟",
        "چرا قانون شماره 5 هیچ‌وقت اجرا نمی‌شود؟",
        "آیا قانون شماره 12 زائد است؟",
        "قانون شماره 3 با کدام قوانین دیگر تعارض دارد؟",
        "در مجموع چند قانون داریم و چندتاشون deny هستند؟",
    ],
    "en": [
        "Can 10.10.25.5 connect to 192.168.50.10 on port 22?",
        "Does 10.0.0.5 have HTTPS access to 172.16.0.10?",
        "What can 10.20.30.40 reach?",
        "Who can reach 192.168.1.100?",
        "Which rules mention IP 10.10.10.10?",
        "Why does rule 5 never fire?",
        "Is rule 12 redundant?",
        "Which rules conflict with rule 3?",
        "How many rules are there, and how many are deny?",
    ],
}


def _query_form_context(lang: str, *, error: str | None = None, question: str = "") -> dict:
    """Shared, non-persistent context for the natural-language query form."""
    context = {
        "lang": lang, "error": error, "question": question,
        "query_examples": QUERY_EXAMPLES.get(lang, QUERY_EXAMPLES["en"]),
    }
    context.update(_t(lang))
    return context


def _translation_view(translation, lang: str) -> dict:
    """Turn the strictly validated model object into safe template data."""
    function_name = translation.function
    args = getattr(translation, f"{function_name}_args")
    values = args.model_dump()
    return {
        "function_label": QUERY_FUNCTION_LABELS[lang][function_name],
        "arguments": [
            {"label": QUERY_ARGUMENT_LABELS[lang][key], "value": str(value)}
            for key, value in values.items()
        ],
    }


def _query_result_view(function_name: str, raw_solution: dict, lang: str) -> dict:
    """Normalize bridge results so templates never render Prolog objects directly."""
    if function_name == "is_allowed":
        decision = str(raw_solution["decision"])
        return {
            "kind": "decision",
            "decision": decision,
            "decision_label": _t(lang).get(f"query_decision_{decision}", decision),
            "entries": [],
            "limitation": None,
        }

    if function_name in {"reachable_from", "who_can_reach", "rules_matching_ip"}:
        list_key = {
            "reachable_from": "destinations",
            "who_can_reach": "sources",
            "rules_matching_ip": "matches",
        }[function_name]
        return {
            "kind": "list",
            "decision": None,
            "decision_label": None,
            "entries": [str(item) for item in raw_solution.get(list_key, [])],
            "limitation": (
                _t(lang)["query_broad_limit"]
                if function_name in {"reachable_from", "who_can_reach"}
                else None
            ),
        }

    if function_name in {"why_shadowed", "is_redundant_rule", "conflicting_rules"}:
        # All three share one shape: a list of "cause" rule IDs from
        # firewall_engine.pl's anomaly detectors (empty list = "no").
        list_key, yes_key, no_key = {
            "why_shadowed": ("shadowing_ids", "query_shadowed_yes", "query_shadowed_no"),
            "is_redundant_rule": ("cause_ids", "query_redundant_yes", "query_redundant_no"),
            "conflicting_rules": ("conflicting_ids", "query_conflict_yes", "query_conflict_no"),
        }[function_name]
        cause_ids = [str(item) for item in raw_solution.get(list_key, [])]
        strings = _t(lang)
        rule_ref = strings["query_rule_ref"]
        return {
            "kind": "rule_check",
            "found": bool(cause_ids),
            "message": strings[yes_key] if cause_ids else strings[no_key],
            "entries": [f"{rule_ref} {rid}" for rid in cause_ids],
            "limitation": None,
        }

    if function_name == "rule_summary":
        strings = _t(lang)
        by_protocol = raw_solution.get("by_protocol", [])
        return {
            "kind": "summary",
            "stats": [
                {"label": strings["query_summary_total"], "value": raw_solution.get("total", 0)},
                {"label": strings["query_summary_allow"], "value": raw_solution.get("allow_count", 0)},
                {"label": strings["query_summary_deny"], "value": raw_solution.get("deny_count", 0)},
            ],
            "by_protocol_label": strings["query_summary_by_protocol"],
            "by_protocol": [
                {"label": str(protocol), "value": count} for protocol, count in by_protocol
            ],
            "limitation": None,
        }

    # Defensive fallback -- should be unreachable since dispatch() only
    # returns one of the function names handled above, but avoids a
    # KeyError turning into an unhandled 500 if a new function is ever
    # added to nl_translator.py without a matching branch here.
    return {"kind": "list", "decision": None, "decision_label": None, "entries": [], "limitation": None}


@app.after_request
def _persist_lang_cookie(response):
    # Only re-set the cookie when the request actually specified a
    # language explicitly (query/form field) -- so a plain page reload
    # with no ?lang= doesn't re-issue the cookie on every request, only
    # when the user actually flips the switch.
    requested = request.values.get("lang")
    if requested in SUPPORTED_LANGS:
        response.set_cookie(
            "firewalllogic_lang", requested, max_age=60 * 60 * 24 * 365, samesite="Lax"
        )
    return response


@app.get("/")
def index():
    lang = _resolve_lang()
    return render_template("index.html", lang=lang, **_t(lang))


@app.get("/query")
def query_form():
    lang = _resolve_lang()
    return render_template("query.html", **_query_form_context(lang))


@app.post("/query")
def query_firewall_rules():
    """Translate one user question, then answer it only with local Prolog facts.

    The uploaded configuration stays in request memory: it is parsed and used
    for this request only, never written to disk or placed in the audit log.
    """
    lang = _resolve_lang()
    question = request.form.get("question", "").strip()
    if not question:
        return render_template(
            "query.html",
            **_query_form_context(lang, error=_t(lang)["query_error_no_question"]),
        ), 400
    if len(question) > 2000:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_question_too_long"], question=question
            ),
        ), 400

    uploaded = request.files.get("config")
    if uploaded is None or not uploaded.filename:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_no_file"], question=question
            ),
        ), 400
    try:
        config_text = uploaded.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_bad_encoding"], question=question
            ),
        ), 400

    rules, parse_errors = parse(config_text)
    if not rules:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_no_rules"], question=question
            ),
        ), 422

    if NLTranslator is None or dispatch is None:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_gemini"], question=question
            ),
        ), 503

    try:
        translation = NLTranslator().translate(question)
        function_name, raw_solution = dispatch(translation, rules)
    except TranslatorConfigurationError:
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_gemini"], question=question
            ),
        ), 503
    except TranslatorAllKeysFailedError:
        # Distinct from TranslatorConfigurationError above (no key was ever
        # set) -- this means one or more GEMINI_API_KEY values ARE set but
        # every one of them failed with an auth/quota-style error. Same
        # user-facing message and status as the generic-failure branch
        # below (no provider/key internals leaked to the web UI), but
        # kept as its own except so this specific, actionable case is
        # distinguishable in server logs from an arbitrary exception.
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_service"], question=question
            ),
        ), 502
    except ValueError as exc:
        # A ValueError here is an intentional clarification request from the
        # validated translator, or a defensively rejected incomplete call.
        message = str(exc) or _t(lang)["query_error_service"]
        return render_template(
            "query.html",
            **_query_form_context(lang, error=message, question=question),
        ), 422
    except Exception:
        # Do not expose provider, Prolog, or file-path internals in a web UI.
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["query_error_service"], question=question
            ),
        ), 502

    context = {
        "lang": lang,
        "question": question,
        "source_name": uploaded.filename,
        "rules_count": len(rules),
        "parse_errors": parse_errors,
        "translation": _translation_view(translation, lang),
        "result": _query_result_view(function_name, raw_solution, lang),
    }
    context.update(_t(lang))
    return render_template("query_report.html", **context)


@app.post("/analyze")
def analyze():
    lang = _resolve_lang()
    uploaded = request.files.get("config")
    strict = request.form.get("strict") == "on"
    if uploaded is None or not uploaded.filename:
        return render_template(
            "index.html", lang=lang, error=_t(lang)["error_no_file"], **_t(lang)
        ), 400

    try:
        config_text = uploaded.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return render_template(
            "index.html",
            lang=lang,
            error=_t(lang)["error_bad_encoding"],
            **_t(lang),
        ), 400

    # Timing window covers parsing + engine reasoning only -- the actual
    # "analysis" work -- not template rendering, which is presentation
    # rather than analysis and would make the number less meaningful for
    # judging how long the engine itself took (e.g. across large configs).
    # time.perf_counter() (monotonic, sub-microsecond resolution) is used
    # instead of time.time() (wall clock) since it can't be affected by
    # system clock adjustments during the request.
    analysis_started_at = time.perf_counter()

    rules, parse_errors = parse(config_text)
    if not rules:
        return render_template(
            "index.html",
            lang=lang,
            error=_t(lang)["error_no_rules"],
            **_t(lang),
        ), 422

    if strict and parse_errors:
        analysis_duration_seconds = time.perf_counter() - analysis_started_at
        audit_log.log_run(
            mode="full",
            source_name=uploaded.filename,
            rules_count=len(rules),
            findings=[],
            parse_errors_count=len(parse_errors),
            analysis_complete=False,
            engine_backend="n/a (strict-blocked before engine ran)",
        )
        context = _report_context(
            uploaded.filename,
            len(rules),
            parse_errors,
            [],
            strict,
            lang,
            strict_blocked=True,
            analysis_duration_seconds=analysis_duration_seconds,
        )
        return render_template("report.html", **context), 422

    findings, engine_error = run_engine(rules, lang=lang)
    if engine_error:
        return render_template(
            "index.html",
            lang=lang,
            error=f"{_t(lang)['error_engine_prefix']}{engine_error}",
            **_t(lang),
        ), 500

    analysis_duration_seconds = time.perf_counter() - analysis_started_at

    audit_log.log_run(
        mode="full",
        source_name=uploaded.filename,
        rules_count=len(rules),
        findings=findings,
        parse_errors_count=len(parse_errors),
        analysis_complete=not parse_errors,
        engine_backend=backend_name(),
    )

    context = _report_context(
        uploaded.filename,
        len(rules),
        parse_errors,
        findings,
        strict,
        lang,
        analysis_duration_seconds=analysis_duration_seconds,
    )
    return render_template("report.html", **context)


@app.errorhandler(413)
def too_large(_error):
    lang = _resolve_lang()
    if request.path == "/query":
        return render_template(
            "query.html",
            **_query_form_context(
                lang, error=_t(lang)["error_file_too_large"], question=request.form.get("question", "")
            ),
        ), 413
    return render_template(
        "index.html", lang=lang, error=_t(lang)["error_file_too_large"], **_t(lang)
    ), 413


def _read_upload(field_name: str, lang: str) -> tuple[str | None, str | None, str | None]:
    """Reads one uploaded file field as UTF-8 text.
    Returns (text, filename, error_message) — error_message is None on success.
    """
    uploaded = request.files.get(field_name)
    if uploaded is None or not uploaded.filename:
        return None, None, _t(lang)["error_both_files_required"]
    try:
        return uploaded.read().decode("utf-8-sig"), uploaded.filename, None
    except UnicodeDecodeError:
        return None, None, _t(lang)["error_bad_encoding_both"]


@app.get("/check-new")
def check_new_form():
    lang = _resolve_lang()
    return render_template("check_new.html", lang=lang, **_t(lang))


@app.post("/check-new")
def check_new():
    lang = _resolve_lang()
    base_text, base_uploaded_name, err = _read_upload("base_config", lang)
    if err:
        return render_template("check_new.html", lang=lang, error=err, **_t(lang)), 400

    new_text, new_uploaded_name, err = _read_upload("new_rules", lang)
    if err:
        return render_template("check_new.html", lang=lang, error=err, **_t(lang)), 400

    analysis_started_at = time.perf_counter()
    result = check_new_rules(base_text, new_text, lang=lang)
    analysis_duration_seconds = time.perf_counter() - analysis_started_at

    if not result.new_rules and not result.base_rules_count:
        return render_template(
            "check_new.html",
            lang=lang,
            error=_t(lang)["error_no_rules_either"],
            **_t(lang),
        ), 422

    if not result.new_rules:
        return render_template(
            "check_new.html",
            lang=lang,
            error=_t(lang)["error_no_new_rules"],
            **_t(lang),
        ), 422

    if result.engine_error:
        return render_template(
            "check_new.html",
            lang=lang,
            error=f"{_t(lang)['error_engine_prefix']}{result.engine_error}",
            **_t(lang),
        ), 500

    audit_log.log_run(
        mode="incremental",
        source_name=f"base={base_uploaded_name} + new={new_uploaded_name}",
        rules_count=result.base_rules_count + len(result.new_rules),
        findings=result.findings,
        parse_errors_count=len(result.base_errors) + len(result.new_errors),
        analysis_complete=not result.base_errors and not result.new_errors,
        engine_backend=backend_name(),
        new_rules_count=len(result.new_rules),
    )

    counts = Counter(f.severity for f in result.findings)
    context = {
        "base_rules_count": result.base_rules_count,
        "new_rules_count": len(result.new_rules),
        "new_rule_ids": [r.id for r in result.new_rules],
        "base_errors": result.base_errors,
        "new_errors": result.new_errors,
        "findings": [_finding_view(f, lang) for f in result.findings],
        "findings_count": len(result.findings),
        "severity_cards": [
            {"key": key, "label": SEVERITY_LABELS[lang][key], "count": counts[key]}
            for key in SEVERITY_ORDER
        ],
        "analysis_complete": not result.base_errors and not result.new_errors,
        "analysis_duration": _format_duration(analysis_duration_seconds, lang),
        "lang": lang,
    }
    context.update(_t(lang))
    return render_template("check_new_report.html", **context)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
