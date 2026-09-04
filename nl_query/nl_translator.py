"""
nl_translator.py — Phase 3 (NL Query), Phase 2 of that sub-plan
=================================================================
Translates a natural-language question (Persian or English) into a
STRUCTURED function call -- one of query_bridge.py's four public
functions, with typed arguments -- rather than a raw Prolog query
string.

WHY STRUCTURED JSON, NOT A RAW PROLOG QUERY STRING (design decision,
documented in FirewallLogic_Phase3_Document_v2.md section 5): letting
an LLM emit free-form Prolog syntax means every downstream consumer
(query_bridge.py, query_engine.pl) has to defend against arbitrary,
possibly malformed or malicious strings. Constraining the LLM's output
to a JSON schema with a closed set of function names and typed fields
means "validation" is just "does this JSON match the schema" -- which
the Gemini API enforces SERVER-SIDE via response_schema, before the
text even reaches this process. This is strictly narrower than
validating a Prolog query string after the fact.

Uses the `google-genai` SDK (package `google.genai`), Google's current
official Python client for the Gemini API. Structured output is
requested via response_mime_type="application/json" + response_schema,
using a Pydantic model as the schema source (the SDK's recommended
approach as of 2026 -- see ai.google.dev/gemini-api/docs/structured-output).
"""

from __future__ import annotations

import os
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator

try:
    from google import genai
    from google.genai import types
    from google.genai import errors as genai_errors
except ImportError:  # Keep the rest of the local web app usable without the optional SDK.
    genai = None
    types = None
    genai_errors = None


class TranslatorConfigurationError(RuntimeError):
    """Raised when the optional Gemini integration is not configured."""


class TranslatorAllKeysFailedError(RuntimeError):
    """Raised when every configured API key failed with an auth/quota-style
    error. Distinct from TranslatorConfigurationError (which means no key
    was ever provided at all) so callers/tests can tell "nothing
    configured" apart from "configured, but every key is dead"."""


# ══════════════════════════════════════════════════════════════════
# 1. Structured output schema -- one Pydantic model per query_bridge
#    function, plus a discriminated wrapper so Gemini picks exactly one.
# ══════════════════════════════════════════════════════════════════

class IsAllowedArgs(BaseModel):
    """Args for query_bridge.is_allowed -- "can X reach Y on protocol/port?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Which firewall chain to check. Default to INPUT if the "
                     "user does not say and the question is about incoming/host access."
    )
    src_ip: str = Field(description="Source IP address, e.g. '10.10.25.5'")
    dst_ip: str = Field(description="Destination IP address, e.g. '192.168.50.10'")
    protocol: Literal["tcp", "udp", "icmp", "any"] = Field(
        description="Protocol. Infer 'tcp' for SSH/HTTP/HTTPS, 'udp' for DNS, "
                     "'any' if the user does not mention a protocol or service."
    )
    port: int = Field(
        description="Destination port. Infer from a named service if given: "
                     "SSH=22, HTTP=80, HTTPS=443, DNS=53. If truly no port or "
                     "service is mentioned, use 0 (caller will handle this case)."
    )


class ReachableFromArgs(BaseModel):
    """Args for query_bridge.reachable_from -- "what can X reach?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Default to OUTPUT if unspecified -- 'what can X reach' "
                     "is usually about outbound access from X."
    )
    src_ip: str = Field(description="Source IP address or CIDR, e.g. '10.20.0.0/16'")


class WhoCanReachArgs(BaseModel):
    """Args for query_bridge.who_can_reach -- "who can reach Y?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Default to INPUT if unspecified -- 'who can reach Y' "
                     "is usually about inbound access to Y."
    )
    dst_ip: str = Field(description="Destination IP address, e.g. '192.168.50.10'")


class RulesMatchingIpArgs(BaseModel):
    """Args for query_bridge.rules_matching_ip -- "which rules mention X?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Default to INPUT if unspecified."
    )
    ip: str = Field(description="The IP address to look up.")
    direction: Literal["src", "dst"] = Field(
        description="'dst' if the user is asking about rules protecting/targeting "
                     "this IP (most common phrasing); 'src' if asking about rules "
                     "that apply when this IP is the traffic source."
    )


class WhyShadowedArgs(BaseModel):
    """Args for query_bridge.why_shadowed -- "why doesn't rule N ever fire?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Which chain rule_id belongs to. Default to INPUT if unspecified."
    )
    rule_id: int = Field(
        description="The rule number/ID the user is asking about, exactly as "
                     "shown in the audit report (e.g. rule 5, قانون شماره ۵)."
    )


class IsRedundantRuleArgs(BaseModel):
    """Args for query_bridge.is_redundant_rule -- "is rule N redundant/useless?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Which chain rule_id belongs to. Default to INPUT if unspecified."
    )
    rule_id: int = Field(description="The rule number/ID the user is asking about.")


class ConflictingRulesArgs(BaseModel):
    """Args for query_bridge.conflicting_rules -- "which rules conflict with rule N?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Which chain rule_id belongs to. Default to INPUT if unspecified."
    )
    rule_id: int = Field(description="The rule number/ID the user is asking about.")


class RuleSummaryArgs(BaseModel):
    """Args for query_bridge.rule_summary -- "how many rules/allow/deny/by protocol?" """
    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(
        description="Which chain to summarize. Default to INPUT if unspecified."
    )


class Translation(BaseModel):
    """Top-level structured output. Gemini fills exactly one of the eight
    optional *_args fields (matching `function`) and leaves the rest null --
    this is the discriminated-union pattern recommended for the
    google-genai SDK, since the SDK's JSON Schema support does not yet
    have first-class Pydantic `Union`-as-oneOf support as clean as
    `anyOf` in the raw schema (see Gemini API structured-output docs,
    "SpamDetails / NotSpamDetails" example) -- this flatter shape is
    less likely to trip up schema validation, and is easy to check in
    Python: read `function`, then pull only the matching non-null arg.
    """
    function: Optional[Literal[
        "is_allowed", "reachable_from", "who_can_reach", "rules_matching_ip",
        "why_shadowed", "is_redundant_rule", "conflicting_rules", "rule_summary",
    ]] = Field(
        default=None,
        description="Which of the eight query functions best answers the question. "
        "Leave null when clarification_needed is set.",
    )
    is_allowed_args: Optional[IsAllowedArgs] = None
    reachable_from_args: Optional[ReachableFromArgs] = None
    who_can_reach_args: Optional[WhoCanReachArgs] = None
    rules_matching_ip_args: Optional[RulesMatchingIpArgs] = None
    why_shadowed_args: Optional[WhyShadowedArgs] = None
    is_redundant_rule_args: Optional[IsRedundantRuleArgs] = None
    conflicting_rules_args: Optional[ConflictingRulesArgs] = None
    rule_summary_args: Optional[RuleSummaryArgs] = None
    clarification_needed: Optional[str] = Field(
        default=None,
        description="If the question is too ambiguous to confidently pick a "
                     "function/chain/IP/rule number (e.g. no IP mentioned at all, "
                     "or a rule-anomaly question with no rule number given), "
                     "explain what's missing here IN THE USER'S OWN LANGUAGE "
                     "instead of guessing. Leave null when confident."
    )

    @model_validator(mode="after")
    def _ensure_coherent_call(self):
        """Reject a partially populated or contradictory tool call.

        The model is allowed to request clarification without inventing a
        function call. Otherwise it must provide exactly the argument object
        for its selected, allow-listed function.
        """
        args_by_function = {
            "is_allowed": self.is_allowed_args,
            "reachable_from": self.reachable_from_args,
            "who_can_reach": self.who_can_reach_args,
            "rules_matching_ip": self.rules_matching_ip_args,
            "why_shadowed": self.why_shadowed_args,
            "is_redundant_rule": self.is_redundant_rule_args,
            "conflicting_rules": self.conflicting_rules_args,
            "rule_summary": self.rule_summary_args,
        }
        supplied = [name for name, value in args_by_function.items() if value is not None]

        if self.clarification_needed:
            if self.function is not None or supplied:
                raise ValueError("clarification responses must not include a function call")
            return self

        if self.function is None:
            raise ValueError("a function is required when clarification is not needed")
        if supplied != [self.function]:
            raise ValueError("exactly the selected function's arguments are required")
        return self


SYSTEM_PROMPT = """You are a precise translator for a firewall query system.
Convert the user's natural-language question (Persian or English) into
EXACTLY ONE structured function call matching the provided schema.

Available functions:
- is_allowed: "Can X reach Y (on some service/port)?" / "Is traffic from X to Y allowed?"
- reachable_from: "What can X reach/access?" (broad survey from one source)
- who_can_reach: "Who/what can reach Y?" / "What can access Y?" (broad survey to one destination)
- rules_matching_ip: "Which rules apply to/mention IP X?"
- why_shadowed: "Why doesn't rule N ever fire/apply?" / "Is rule N shadowed?"
  (a rule is 'shadowed' when an earlier, broader rule with a conflicting
  action already matches everything it would match, so it never runs)
- is_redundant_rule: "Is rule N redundant/unnecessary/useless?"
  (redundant = a different earlier rule with the SAME action already
  covers everything it covers)
- conflicting_rules: "Which rules conflict/contradict/correlate with rule N?"
  (two rules that partially overlap with opposite actions, so the result
  depends on rule order)
- rule_summary: "How many rules are there?" / "How many allow vs deny rules?" /
  "What's the protocol breakdown?" (a chain-wide count, no specific rule
  or IP needed)

Rules:
- Extract IP addresses and CIDR blocks exactly as the user wrote them.
- Infer well-known service names to ports/protocols (SSH=22/tcp, HTTP=80/tcp,
  HTTPS=443/tcp, DNS=53/udp) when the user names a service instead of a port number.
- Rule numbers/IDs (for why_shadowed, is_redundant_rule, conflicting_rules) refer
  to the rule numbering already shown in this tool's own audit report -- extract
  the integer exactly as stated (e.g. "rule 5", "قانون شماره ۵", "پنجمین قانون").
  Convert Persian digits/number words to the plain integer.
- If the user's question genuinely lacks a required IP address or rule number,
  or is not about firewall access/rules at all, set clarification_needed in the
  user's own language and leave function and every *_args field null. Do not guess.
- Never invent an IP address, port, chain, or rule number that was not stated or
  clearly implied.
"""


# ══════════════════════════════════════════════════════════════════
# 2. Translator
# ══════════════════════════════════════════════════════════════════

class NLTranslator:
    # HTTP status codes that mean "this specific key/credential is the
    # problem" (bad key, revoked key, out of quota, rate-limited) rather
    # than "the request itself is wrong". Only these trigger a retry with
    # the next configured key -- a 400 (malformed request) would fail
    # identically on every key since this project always sends the same
    # fixed schema, so retrying it would just waste the remaining keys
    # and hide the real error.
    _KEY_LEVEL_STATUS_CODES = frozenset({401, 403, 429})

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """Create a translator without ever accepting a hard-coded secret.

        ``GEMINI_API_KEY`` is preferred, with ``GOOGLE_API_KEY`` accepted for
        compatibility with the official SDK. Either may hold MULTIPLE keys
        separated by commas (e.g. ``GEMINI_API_KEY=key1,key2,key3``) -- see
        translate() for the fallback behavior across them. The model
        remains configurable because availability changes over time; the
        default is a currently documented low-latency Gemini model.
        """
        if genai is None or types is None:
            raise TranslatorConfigurationError(
                "Gemini support is not installed. Install the project's Python dependencies."
            )
        raw_keys = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not raw_keys:
            raise TranslatorConfigurationError(
                "Gemini is not configured. Set GEMINI_API_KEY before using natural-language queries."
            )
        # Split on commas, trim whitespace, and drop empties so a stray
        # trailing comma or extra space in the .env value (e.g.
        # "key1, key2,") doesn't produce a blank "key" that would always
        # fail first. Order is preserved -- keys are tried left to right.
        self._api_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        if not self._api_keys:
            raise TranslatorConfigurationError(
                "Gemini is not configured. Set GEMINI_API_KEY before using natural-language queries."
            )
        self.model = model or os.environ.get(
            "FIREWALLLOGIC_GEMINI_MODEL", "gemini-3.5-flash-lite"
        )
        # One client is built per key up front (cheap -- genai.Client()
        # does not make a network call) rather than lazily inside
        # translate(), so a key that fails to even construct a client
        # (rare, but possible with a structurally invalid key) is
        # equally covered by the same try/except-and-advance loop below.
        self._clients: list[genai.Client] = []
        for key in self._api_keys:
            self._clients.append(genai.Client(api_key=key))
        # Index of the key that most recently worked. Starting each
        # translate() call from here (rather than always from index 0)
        # means once a working key is found, subsequent calls don't
        # keep re-trying already-dead earlier keys on every single
        # question -- only when the current one itself fails.
        self._last_working_index = 0

    def translate(self, nl_question: str) -> Translation:
        """Returns a validated Translation. Raises on API/schema failure --
        callers should catch and surface a user-facing error rather than
        silently falling back to guessing, per this module's design note.

        Multi-key fallback: if the current key fails with an auth- or
        quota-style error (401/403/429, or a network-level error that
        never got an HTTP response at all -- e.g. DNS failure, connection
        refused), the next configured key is tried, in order, wrapping
        around at most once through the full list. A schema-mismatch
        (SDK-side ValueError/pydantic ValidationError) or any other
        non-key-level error is raised immediately without rotating,
        since a different key would not change that outcome.
        """
        num_keys = len(self._clients)
        last_error: Exception | None = None

        for attempt in range(num_keys):
            index = (self._last_working_index + attempt) % num_keys
            client = self._clients[index]
            try:
                response = client.models.generate_content(
                    model=self.model,
                    contents=f"{SYSTEM_PROMPT}\n\nUser question: {nl_question}",
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=Translation,
                    ),
                )
            except genai_errors.APIError as e:
                if getattr(e, "code", None) in self._KEY_LEVEL_STATUS_CODES and attempt < num_keys - 1:
                    last_error = e
                    continue  # try the next key
                raise  # last key, or a non-key-level API error -- don't hide it
            except Exception as e:
                # Network-level failures (no HTTP response at all -- e.g.
                # requests/httpx connection errors) come through as
                # whatever exception the underlying transport raises,
                # not genai_errors.APIError. Treat those as key-level
                # too (rotating keys is harmless and occasionally
                # helps, e.g. a key pinned to a different, reachable
                # region or project), but only while keys remain.
                if attempt < num_keys - 1:
                    last_error = e
                    continue
                raise

            # Success -- remember this key so the next call starts here.
            self._last_working_index = index
            # SDK releases have exposed structured results through both
            # ``parsed`` and ``text``. Accept either form, then always run
            # our own coherence validation above before a value can reach
            # the Prolog bridge.
            parsed = getattr(response, "parsed", None)
            if isinstance(parsed, Translation):
                return parsed
            if parsed is not None:
                return Translation.model_validate(parsed)
            return Translation.model_validate_json(response.text)

        # Unreachable in practice (the loop above always either returns or
        # raises on its last iteration), but keeps type-checkers and any
        # future refactor honest about the fallthrough case.
        raise TranslatorAllKeysFailedError(
            f"All {num_keys} configured Gemini API key(s) failed. Last error: {last_error}"
        )


# ══════════════════════════════════════════════════════════════════
# 3. Dispatch helper -- bridges Translation -> query_bridge.py call
# ══════════════════════════════════════════════════════════════════

def dispatch(translation: Translation, rules: list) -> tuple[str, dict]:
    """Calls the appropriate query_bridge.py function based on a
    Translation, returning (function_name, result_dict) for the caller
    (webapp.py's future /query route) to render.

    Raises ValueError if clarification_needed is set, or if the expected
    args field for `function` is missing (defensive -- should not happen
    if Gemini honored the schema, but a Pydantic schema can't itself
    enforce "args field for the chosen function must be non-null").
    """
    try:
        from . import query_bridge as qb
    except ImportError:  # Allows ``python nl_query/nl_translator.py`` style use too.
        import query_bridge as qb

    if translation.clarification_needed:
        raise ValueError(translation.clarification_needed)

    if translation.function is None:
        raise ValueError("The model did not select a query function.")

    if translation.function == "is_allowed":
        a = translation.is_allowed_args
        if a is None:
            raise ValueError("Model chose is_allowed but did not provide arguments.")
        if a.port == 0:
            raise ValueError(
                "Could not determine which port/service the question refers to."
            )
        result = qb.is_allowed(rules, a.chain, a.src_ip, a.dst_ip, a.protocol, a.port)

    elif translation.function == "reachable_from":
        a = translation.reachable_from_args
        if a is None:
            raise ValueError("Model chose reachable_from but did not provide arguments.")
        result = qb.reachable_from(rules, a.chain, a.src_ip)

    elif translation.function == "who_can_reach":
        a = translation.who_can_reach_args
        if a is None:
            raise ValueError("Model chose who_can_reach but did not provide arguments.")
        result = qb.who_can_reach(rules, a.chain, a.dst_ip)

    elif translation.function == "rules_matching_ip":
        a = translation.rules_matching_ip_args
        if a is None:
            raise ValueError("Model chose rules_matching_ip but did not provide arguments.")
        result = qb.rules_matching_ip(rules, a.chain, a.ip, a.direction)

    elif translation.function == "why_shadowed":
        a = translation.why_shadowed_args
        if a is None:
            raise ValueError("Model chose why_shadowed but did not provide arguments.")
        result = qb.why_shadowed(rules, a.chain, a.rule_id)

    elif translation.function == "is_redundant_rule":
        a = translation.is_redundant_rule_args
        if a is None:
            raise ValueError("Model chose is_redundant_rule but did not provide arguments.")
        result = qb.is_redundant_rule(rules, a.chain, a.rule_id)

    elif translation.function == "conflicting_rules":
        a = translation.conflicting_rules_args
        if a is None:
            raise ValueError("Model chose conflicting_rules but did not provide arguments.")
        result = qb.conflicting_rules(rules, a.chain, a.rule_id)

    elif translation.function == "rule_summary":
        a = translation.rule_summary_args
        if a is None:
            raise ValueError("Model chose rule_summary but did not provide arguments.")
        result = qb.rule_summary(rules, a.chain)

    else:
        raise ValueError(f"Unknown function: {translation.function}")

    if not result.success:
        raise RuntimeError(result.error or "Query failed with no error message.")

    return translation.function, result.raw_solution
