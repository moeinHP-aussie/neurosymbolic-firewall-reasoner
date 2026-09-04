"""
bridge.py — Phase 3 (pyswip-first, subprocess fallback)
=========================================================
Connects the Python parser to the Prolog engine via pyswip. pyswip is
ALWAYS tried first. If it's unavailable at import time (not installed,
or the SWI-Prolog shared library can't be found) OR it fails at call
time for any reason (engine error, a bug we haven't seen yet, ...),
run_engine() automatically falls back to the subprocess backend for
that call and reports which backend actually served the request.
pyswip is retried on every subsequent call -- a transient failure does
not permanently disable it for the rest of the process.

WHY pyswip INSTEAD OF janus_swi:
This project's original proposal specified pyswip, and it is also the
better fit operationally here:
  - pyswip has no SWI-Prolog version floor (janus_swi requires SWI-Prolog
    >= 9.1.12; some lab/demo machines still run older SWI-Prolog, and
    "the anomaly report doesn't work because Prolog is one point release
    too old" is exactly the kind of presentation-day failure this
    project cannot afford).
  - pyswip's API (Prolog.query(), Functor, registerForeign) is older,
    more widely documented, and is what the internship proposal itself
    named -- so this also keeps the codebase consistent with the
    project's own written plan.
  - Both are in-process/embedded (via SWI-Prolog's C foreign interface),
    so neither pays the ~300ms per-run subprocess startup cost. Raw
    single-call latency differs (pyswip's ctypes-based FFI has more
    per-call overhead than janus's purpose-built C extension), but for
    this project's call pattern -- one query per rule assert, one query
    for the report -- that difference is not perceptible.

MODULE-QUALIFICATION NOTE (please read before assuming this "just
works" the same way janus's version did):
firewall_engine.pl declares rule/8 as user:rule/8 specifically (see
that file's "rule/8 IMPORTANT MODULE NOTE") because firewall_engine.pl
is itself a module -- without the user: prefix, its own dynamic
declaration would create a private, module-local rule/8 that the
Python-asserted facts could never reach. The janus version of this
file asserted into user: explicitly for exactly that reason.

pyswip's Prolog.query()/assertz()/retractall() calls, run from Python,
execute in the `user` module by default -- the SAME module
firewall_engine.pl's declaration targets. So the plain, unqualified
`rule(...)` calls used below (no `user:` prefix) already land in the
correct predicate.

VERIFIED (previously an open question -- see git history for the old
"has NOT been exercised" wording): this WAS exercised against a real
SWI-Prolog 9.0.4 + pyswip 0.3.3 install, including a full run against
demo_university_firewall.rules (27 rules, 5 findings) via both
run_engine() directly and the /analyze Flask endpoint. Results matched
the subprocess backend exactly. If querying ever DOES appear to
silently see zero rules despite successful assertz() calls on some
other machine/version combination, that mismatch -- a pyswip query
running in some module other than `user` -- is still the first thing
to check; the fix would be reintroducing an explicit `user:` prefix on
every query/assertz/retractall call in _run_via_pyswip below, mirroring
the janus version.

WHY THE FLATTEN-TO-LIST WRAPPER IS KEPT (find_all_anomalies_janus/1,
now also used by the pyswip backend, despite the name):
janus_swi's Prolog<->Python conversion table is what originally forced
firewall_engine.pl to expose a version of find_all_anomalies/1 that
returns plain lists instead of finding/5 compound terms (see that
predicate's docstring in firewall_engine.pl). pyswip does NOT have the
same hard restriction -- Functor lets you construct and inspect
arbitrary compound terms from Python. So in principle the pyswip
backend could call find_all_anomalies/1 directly and unpack finding/5
terms via .args.

We deliberately do NOT do that here, for two reasons:
  1. Phase 2 is signed off and tested exhaustively as-is (per the
     project owner). find_all_anomalies_janus/1 is part of that frozen,
     tested surface. Reusing it costs nothing and avoids touching
     firewall_engine.pl's tested predicates just to satisfy a backend
     preference.
  2. A single flattened-list shape means both backends (pyswip here,
     subprocess below) and any future backend consume the exact same
     Prolog-side contract. If firewall_engine.pl's finding/5 arity or
     field order ever changes, there is exactly one place
     (finding_to_list/2 in firewall_engine.pl) that has to change to
     keep every backend correct, instead of one conversion per backend.
The predicate keeps its old name (`_janus_...`) rather than being
renamed, because renaming a signed-off, already-tested Phase 2
predicate is exactly the kind of drive-by change that risks
invalidating prior verification for a purely cosmetic reason. A
comment at its definition site (firewall_engine.pl) notes it is now
backend-agnostic.

Installation (system with SWI-Prolog installed and on the library path):
    pip install pyswip

pyswip API notes used below:
  - Prolog.consult(path) is a dedicated method (not routed through
    query()) and accepts a pathlib.Path directly -- no manual path
    quoting required, unlike building a `consult('...')` query string
    by hand.
  - Prolog.assertz(fact_string) and Prolog.query("retractall(...)")
    are also dedicated/plain calls; assertz() in particular is used
    directly below rather than via query("assertz(...)"), since that
    is pyswip's documented idiomatic form.
  - Prolog.query(goal) returns a GENERATOR, not a list -- a query that
    is never iterated never actually runs on the Prolog side. Every
    call below is wrapped in list(...) for exactly this reason, even
    when the solutions themselves are discarded (e.g. retractall).

Usage:
    from bridge import run_engine
    findings, error = run_engine(rules)
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from parser import Rule

# ── locate engine files ────────────────────────────────────────────
_HERE       = Path(__file__).parent
ENGINE_PL   = _HERE / "firewall_engine.pl"
SUBNET_PL   = _HERE / "ip_subnet.pl"

# ── detect pyswip at import time ───────────────────────────────────
# This only tells us the *package* (and the SWI-Prolog shared library
# it binds to) are importable -- it does NOT guarantee every call will
# succeed (a query can still raise, the global engine can still end up
# in a bad state, etc.), so run_engine() below never treats this flag
# as a permanent decision. It's an initial hint, not a guarantee.
try:
    from pyswip import Prolog
    _PYSWIP_IMPORTABLE = True
except Exception:
    # pyswip's import can fail with ImportError (package missing) OR
    # with other exceptions raised while it locates/loads the
    # SWI-Prolog shared library (e.g. OSError on some platforms if
    # swipl isn't on the library path) -- both mean "not usable here".
    _PYSWIP_IMPORTABLE = False

# ── which backend actually served the most recent run_engine() call ─
# Updated on every call; read via backend_name() for logging/reporting
# (e.g. showing the user which path was used, or surfacing degraded
# performance if pyswip keeps failing over).
_last_backend_used = "pyswip" if _PYSWIP_IMPORTABLE else "subprocess"

# ── the single shared pyswip engine instance ───────────────────────
# pyswip.Prolog wraps one embedded, process-global SWI-Prolog engine --
# unlike janus_swi there is no per-call "handle", so we keep exactly
# one Prolog() instance for the life of this module and reuse it
# across every run_engine() call. Constructing more than one Prolog()
# does not start a second engine (it is effectively a singleton), so
# there is no advantage to re-creating it per call, only the cost of
# re-doing consult/ensure_loaded work.
_prolog: Optional["Prolog"] = None


def _get_prolog() -> "Prolog":
    """Returns the module-wide pyswip engine, creating it on first use."""
    global _prolog
    if _prolog is None:
        _prolog = Prolog()
    return _prolog


# ══════════════════════════════════════════════════════════════════
# 1.  Data model
# ══════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    type:         str   # shadowing | redundancy | correlation | generalization
    severity:     str   # critical | high | medium | low
    primary_id:   int
    secondary_id: int
    explanation:  str

    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def severity_rank(self) -> int:
        return self._SEVERITY_ORDER.get(self.severity, 99)


# ══════════════════════════════════════════════════════════════════
# 2.  Public entry point
# ══════════════════════════════════════════════════════════════════

def run_engine(
    rules: list[Rule],
    timeout_seconds: int = 120,
    lang: str = "fa",
) -> tuple[list[Finding], Optional[str]]:
    """
    Assert *rules* into the Prolog engine, run the anomaly detector,
    and return (findings, error_string). error_string is None on success.

    lang: "fa" (default, unchanged historical behavior) or "en".
    Controls the language of every Explanation string produced by the
    Prolog engine (see firewall_engine.pl §4a) AND of the chain-label
    prefix added below, which is the one piece of report text that has
    always lived in Python rather than Prolog.

    Backend selection policy (pyswip-first, always-retry):
      1. If pyswip couldn't even be imported (or its underlying
         SWI-Prolog shared library couldn't be loaded), go straight to
         subprocess -- there's no point attempting a call that will
         certainly fail on ImportError.
      2. Otherwise, ALWAYS attempt pyswip first, on every call. If it
         raises for any reason, fall back to subprocess for THIS call
         only and log why -- the next call tries pyswip again from
         scratch. We deliberately do not "remember" a pyswip failure
         and permanently disable it: a failure could be transient
         (e.g. the shared global engine ending up mid-query in a bad
         state) and silently downgrading every future call to the
         slower backend for the rest of the process would be a worse
         outcome than retrying.

    NOTE ON timeout_seconds AND THE pyswip BACKEND: unlike the
    subprocess backend (a real OS process, killable on timeout),
    pyswip runs the query in-process with no built-in per-call
    timeout. timeout_seconds is honored for the subprocess backend
    only. In practice this project's queries are pre-filtered by the
    sweep-line candidate-pair step (see firewall_engine.pl) precisely
    so this is not a practical concern -- but it's a real asymmetry
    between the two backends worth knowing about, not silently papered
    over. If a hang ever were observed with pyswip, it would need to
    be enforced from Python (e.g. via a watchdog thread) since pyswip
    itself provides no query cancellation.
    """
    if not rules:
        return [], None

    # iptables/nftables evaluate rules within a chain.  Comparing INPUT with
    # FORWARD, for example, creates false positives because those rules are
    # never competing for the same first-match decision.  Keep the Prolog
    # rule/8 schema unchanged and run its proven detector once per chain.
    rules_by_chain: dict[str, list[Rule]] = {}
    for rule in rules:
        rules_by_chain.setdefault(rule.chain, []).append(rule)

    chain_label = "زنجیره" if lang == "fa" else "Chain"

    all_findings: list[Finding] = []
    for chain, chain_rules in rules_by_chain.items():
        findings, error = _run_single_chain(chain_rules, timeout_seconds, lang)
        if error is not None:
            return [], f"chain {chain!r}: {error}"
        for finding in findings:
            finding.explanation = f"{chain_label} {chain}:\n{finding.explanation}"
        all_findings.extend(findings)

    all_findings.sort(key=lambda f: f.severity_rank())
    return all_findings, None


def _run_single_chain(
    rules: list[Rule], timeout_seconds: int, lang: str = "fa"
) -> tuple[list[Finding], Optional[str]]:
    """Run the existing Prolog rule/8 detector for one firewall chain."""
    global _last_backend_used

    if _PYSWIP_IMPORTABLE:
        findings, error = _run_via_pyswip(rules, lang)
        if error is None:
            _last_backend_used = "pyswip"
            return findings, None
        print(f"[bridge] pyswip backend failed ({error}) — falling back to subprocess for this call")

    _last_backend_used = "subprocess"
    return _run_via_subprocess(rules, timeout_seconds, lang=lang)


def backend_name() -> str:
    """
    Returns the backend ('pyswip' or 'subprocess') that served the most
    recent run_engine() call. Before the first call, reflects whether
    pyswip was importable at all -- useful for logging/reporting,
    e.g. showing the user which path is currently active or warning
    them if pyswip keeps failing over.
    """
    return _last_backend_used


# ══════════════════════════════════════════════════════════════════
# 3.  pyswip backend  (fast, in-process, embedded SWI-Prolog engine)
# ══════════════════════════════════════════════════════════════════

def _run_via_pyswip(rules: list[Rule], lang: str = "fa") -> tuple[list[Finding], Optional[str]]:
    """
    Steps:
      1. Load ip_subnet.pl and firewall_engine.pl into the embedded
         Prolog engine (idempotent -- safe to call on every run_engine()
         call; consult/1 re-reading an unchanged file is a cheap no-op
         relative to everything else this function does).
      2. Retract any rule/8 facts from a previous call so this engine
         session stays stateless between run_engine() invocations --
         pyswip's engine is a persistent, process-wide singleton
         (see _get_prolog() above), so without this step, facts from
         an earlier config file would silently leak into the next
         run's report.
      3. Assert every rule/8 fact from the current config.
      4. Query find_all_anomalies_janus/2 with the requested lang (see
         this module's docstring for why the "_janus" name is kept
         regardless of backend) and read back a Python list of
         5-element lists, already rendered in that language.
      5. Convert each 5-element list to a Finding dataclass.

    pyswip's query API: Prolog.query(goal_string) returns a GENERATOR
    of solution dicts (one dict per solution, keys are the goal's
    uppercase variable names as strings, values already converted to
    native Python types for atoms/numbers/lists). This project's
    queries are all deterministic (assert a fact, retract, or collect
    one aggregated list) so we only ever need the first solution --
    but pyswip still requires driving the generator via next()/list()
    to actually execute the query; a Prolog.query(...) call that is
    never iterated never actually runs. This is a common pyswip
    footgun and is the reason every call below is wrapped in
    list(...) rather than left as a bare expression.

    Prolog → Python data conversion (pyswip built-in):
      Prolog atom            → Python str
      Prolog int              → Python int
      Prolog list              → Python list
      Prolog finding(...)   → would come back as a pyswip Term/Functor
                                 object, NOT a plain Python value -- this
                                 is exactly why find_all_anomalies_janus/2
                                 is used instead of find_all_anomalies/2:
                                 it flattens each finding/5 into a plain
                                 5-element Prolog list on the Prolog side,
                                 which pyswip DOES convert natively, so
                                 no Functor/Term unpacking is needed here.
    """
    if lang not in ("fa", "en"):
        lang = "fa"
    try:
        prolog = _get_prolog()

        # ── load engine (idempotent) ───────────────────────────────
        # Prolog.consult() is a dedicated pyswip method (not routed
        # through query()) and accepts a pathlib.Path directly -- no
        # manual string-quoting of the path needed, which sidesteps
        # any Windows backslash/quoting edge cases entirely. Re-consulting
        # an already-loaded file on every call is cheap and guarantees
        # we're never running against stale engine state.
        prolog.consult(SUBNET_PL)
        prolog.consult(ENGINE_PL)

        # ── clear previous rule set, then assert the new one ───────
        # See the MODULE-QUALIFICATION NOTE below: rule/8 is declared
        # as user:rule/8 in firewall_engine.pl (see that file's "rule/8
        # IMPORTANT MODULE NOTE"), and pyswip's queries run in the
        # `user` module by default -- the same module the engine's own
        # :- dynamic user:rule/8 declaration targets. So an unqualified
        # retractall(rule(...)) / assertz(rule(...)) here already lands
        # in user:rule/8, the same predicate the engine reads from.
        # This mirrors the subprocess backend, whose generated script
        # also asserts plain rule(...) facts with no module prefix
        # (see _build_prolog_script below) into that same default
        # `user` context.
        list(prolog.query("retractall(rule(_,_,_,_,_,_,_,_))"))

        for rule in rules:
            fact_str = rule.to_prolog_fact().rstrip(".")
            prolog.assertz(fact_str)

        # ── run engine ────────────────────────────────────────────
        # find_all_anomalies_janus(+Lang, -ListOfLists) is deterministic
        # -- it collects everything into one list and succeeds exactly
        # once, so we only ever consume the first (only) solution.
        solutions = list(prolog.query(f"find_all_anomalies_janus({lang}, Findings)"))
        if not solutions:
            return [], "find_all_anomalies_janus/2 failed unexpectedly"

        findings = _pyswip_list_to_findings(solutions[0]["Findings"])
        findings.sort(key=lambda f: f.severity_rank())
        return findings, None

    except Exception as e:
        return [], f"pyswip engine error: {e}"


def _pyswip_list_to_findings(list_of_lists) -> list[Finding]:
    """
    Converts the Python list of 5-element lists returned by
    find_all_anomalies_janus/1 into Finding objects.

    Each element is a plain Python list [type, severity, primary_id,
    secondary_id, explanation]. pyswip converts Prolog atoms to Python
    str and Prolog integers to Python int automatically inside a
    converted list, same as janus does -- no compound-term handling is
    needed here, because that flattening already happened on the
    Prolog side, inside find_all_anomalies_janus/1 (see
    firewall_engine.pl). One pyswip-specific wrinkle: string-valued
    Prolog atoms sometimes arrive as pyswip's own bytes-like Atom
    wrapper rather than a plain str depending on pyswip version, so
    every field is still explicitly cast below (str()/int()) exactly
    as the janus version did -- this makes the conversion robust to
    that difference instead of silently depending on it.
    """
    results = []
    for item in list_of_lists:
        try:
            ftype, severity, primary_id, secondary_id, explanation = item
            results.append(Finding(
                type=str(ftype),
                severity=str(severity),
                primary_id=int(primary_id),
                secondary_id=int(secondary_id),
                explanation=str(explanation),
            ))
        except (ValueError, TypeError):
            continue  # malformed entry — skip rather than crash
    return results


# ══════════════════════════════════════════════════════════════════
# 4.  Subprocess backend  (fallback, ~300 ms startup overhead)
# ══════════════════════════════════════════════════════════════════

def _build_prolog_script(rules: list[Rule], lang: str = "fa") -> str:
    """Builds a self-contained Prolog script for the subprocess path."""
    if lang not in ("fa", "en"):
        lang = "fa"
    fact_lines = "\n".join(r.to_prolog_fact() for r in rules)
    # SWI-Prolog treats backslashes in quoted atoms as escapes.  Windows paths
    # therefore need POSIX separators before they are embedded in the script.
    subnet_path = SUBNET_PL.resolve().as_posix().replace("'", "\\\\'")
    engine_path = ENGINE_PL.resolve().as_posix().replace("'", "\\\\'")
    return f"""\
:- encoding(utf8).
% `:- encoding(utf8)` above only controls how THIS SCRIPT FILE is read.
% It does not touch the encoding of current_output/user_error, which is
% what format/2 below actually writes through. When stdout is piped to
% a subprocess.run() capture (rather than a real terminal), SWI-Prolog
% does not reliably default that stream to UTF-8 on every platform --
% when it doesn't, format("~w", [Explanation]) falls back to writing
% non-ASCII characters as literal \\uXXXX escape sequences instead of
% raw UTF-8 bytes, which is exactly the "sayehandagi\\u0628\\u062d..."
% -style corruption this fixes. Setting both streams explicitly, right
% after the encoding/1 directive and before any Persian text is
% written, makes the subprocess backend's output correct regardless of
% the parent process's locale.
:- set_stream(current_output, encoding(utf8)).
:- set_stream(user_error, encoding(utf8)).
:- use_module('{subnet_path}').
:- consult('{engine_path}').
:- dynamic user:rule/8.
:- multifile user:rule/8.

{fact_lines}

:- initialization(main, main).

main :-
    find_all_anomalies({lang}, Findings),
    forall(
        member(finding(Type, Severity, PrimaryID, SecondaryID, Explanation), Findings),
        format("FINDING|~w|~w|~w|~w|~w~n",
               [Type, Severity, PrimaryID, SecondaryID, Explanation])
    ),
    halt.
"""


def _run_via_subprocess(
    rules: list[Rule],
    timeout_seconds: int,
    swipl_path: str = "swipl",
    lang: str = "fa",
) -> tuple[list[Finding], Optional[str]]:
    """Subprocess fallback — writes a temp Prolog script and runs swipl."""
    script = _build_prolog_script(rules, lang)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".pl", delete=False, encoding="utf-8"
    ) as f:
        f.write(script)
        script_path = f.name

    try:
        result = subprocess.run(
            [swipl_path, "-q", script_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            # Without an explicit encoding, subprocess.run(text=True) falls
            # back to locale.getpreferredencoding(), which is UTF-8 on most
            # Linux setups but is frequently a legacy codepage (e.g.
            # cp1252/cp936) on Windows. The Prolog side now always writes
            # UTF-8 (see the set_stream/2 directives in
            # _build_prolog_script above), so decoding as anything else
            # here would silently turn correct UTF-8 bytes into mojibake
            # regardless of that fix.
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return [], f"swipl not found at {swipl_path!r}"
    except subprocess.TimeoutExpired:
        return [], f"Engine timed out after {timeout_seconds}s"
    finally:
        os.unlink(script_path)

    if result.returncode != 0 and "FINDING" not in result.stdout:
        return [], f"Prolog engine error:\n{result.stderr.strip()}"

    findings = _parse_subprocess_output(result.stdout)
    findings.sort(key=lambda f: f.severity_rank())
    return findings, None


def _parse_subprocess_output(output: str) -> list[Finding]:
    """Parses FINDING|... lines from the subprocess engine's stdout."""
    findings = []
    for line in output.splitlines():
        if not line.startswith("FINDING|"):
            continue
        parts = line.split("|", 5)
        if len(parts) < 6:
            continue
        _, ftype, severity, primary, secondary, explanation = parts
        try:
            findings.append(Finding(
                type=ftype.strip(),
                severity=severity.strip(),
                primary_id=int(primary.strip()),
                secondary_id=int(secondary.strip()),
                explanation=explanation.strip(),
            ))
        except (ValueError, IndexError):
            continue
    return findings


# ══════════════════════════════════════════════════════════════════
# 5.  Standalone test
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from parser import parse

    SAMPLE = """
*filter
:FORWARD DROP [0:0]
-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT
-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p tcp --dport 80 -j DROP
-A FORWARD -s 192.168.1.0/24 -d 10.1.0.0/16 -p tcp --dport 443 -j ACCEPT
-A FORWARD -s 192.168.1.0/24 -d 10.1.5.0/24  -p tcp --dport 443 -j ACCEPT
-A FORWARD -j DROP
COMMIT
"""

    print(f"[bridge] pyswip importable: {_PYSWIP_IMPORTABLE}")
    rules, _ = parse(SAMPLE)
    findings, err = run_engine(rules)
    print(f"[bridge] backend used for this run: {backend_name()}")
    if err:
        print("ERROR:", err)
    else:
        print(f"Found {len(findings)} anomaly(s):\n")
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.type}: rule #{f.primary_id} vs #{f.secondary_id}")
