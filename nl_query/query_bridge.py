"""
query_bridge.py — Phase 3 (NL Query)
=====================================
Connects a single, already-chosen firewall chain's rule/8 facts to
query_engine.pl's read-only query predicates.

DESIGN CONSTRAINT (mirrors incremental.py's own note): this module does
NOT modify firewall_engine.pl, ip_subnet.pl, bridge.py, or parser.py. It
reuses parser.py's ip_to_prolog() (the SAME function the config parser
itself uses) to turn a raw IP string from a user's question into an
ip4(...)/ip6(...) term string, and reuses bridge.py's pyswip singleton
pattern (_get_prolog()) so this file does not spin up a second, separate
embedded Prolog engine alongside the one bridge.py already owns.

Two backends, same choice bridge.py already made:
  - pyswip, if importable (fast, in-process)
  - subprocess fallback otherwise

WHY A SEPARATE MODULE INSTEAD OF EXTENDING bridge.py DIRECTLY:
bridge.py's run_engine() is the tested, signed-off Phase 2 surface
(see that file's own docstring: "Phase 2 is signed off and tested
exhaustively as-is"). Adding query-specific asserts/retracts into that
file risks touching frozen, verified code. query_bridge.py instead
imports bridge.py's pyswip plumbing (the engine singleton + consult
pattern) and adds a parallel, independent entry point for queries only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from parser import ip_to_prolog, port_to_prolog, Rule

# Reuse bridge.py's already-tested pyswip detection + engine singleton
# instead of re-implementing "is pyswip importable" / "one shared engine"
# a second time. If pyswip isn't importable, bridge.py's own subprocess
# fallback path is proven; this module's subprocess path below mirrors
# it directly rather than importing private helpers from bridge.py.
import bridge

from pathlib import Path

# IMPORTANT (found while testing): query_engine.pl's own
# ":- use_module(ip_subnet)." resolves the name 'ip_subnet' relative to
# the directory query_engine.pl is consulted FROM. Since ip_subnet.pl
# lives in bridge._HERE (the main project folder, alongside
# firewall_engine.pl -- see bridge.py's own ENGINE_PL/SUBNET_PL), this
# only works if query_engine.pl is ALSO placed in that same folder, not
# in a separate nl_query/ subdirectory. Verified with a minimal
# reproduction: use_module(name) with a bare relative name fails with
# "source_sink `name` does not exist" the moment the consulting file
# lives in a different directory than the target module file.
QUERY_ENGINE_PL = bridge._HERE / "query_engine.pl"
SUBNET_PL = bridge.SUBNET_PL
ENGINE_PL = bridge.ENGINE_PL  # not consulted here, but kept for parity/logging


# ══════════════════════════════════════════════════════════════════
# 1. Data model
# ══════════════════════════════════════════════════════════════════

@dataclass
class QueryResult:
    predicate: str                 # which query_engine.pl predicate ran
    success: bool
    raw_solution: Optional[dict] = None   # pyswip solution dict, if any
    error: Optional[str] = None
    backend: str = "unknown"


# ══════════════════════════════════════════════════════════════════
# 2. IP / port string -> Prolog term helpers
# ══════════════════════════════════════════════════════════════════

def _ip_term(ip_string: str) -> str:
    """Wraps parser.py's own ip_to_prolog() -- the exact function the
    config parser uses -- so a bare address like "10.10.25.5" becomes
    "ip4(10,10,25,5,32)" the same way it would if it had appeared in an
    actual config file. No second implementation of CIDR parsing exists
    anywhere in this project; this is the only one, reused here as-is.
    """
    return ip_to_prolog(ip_string)


def _port_int(port) -> int:
    """query_engine.pl's is_allowed/5 takes a bare port INTEGER (see
    that predicate's docstring: "Port is checked against DstPort only"),
    not a port(N) term -- because the query is always about one single
    port, never a range, when a user asks "can X reach Y on port N".
    parser.py's port_to_prolog() returns a Prolog TERM STRING like
    "port(22)" (built for asserting into rule/8), so a query about a
    single port needs the bare int, not that wrapped term string.
    """
    if isinstance(port, int):
        return port
    return int(port)


# ══════════════════════════════════════════════════════════════════
# 3. Loading one chain's rules into the engine
# ══════════════════════════════════════════════════════════════════

def _assert_chain(prolog, rules: list[Rule], chain: str) -> int:
    """Retracts any previously-asserted rule/8 facts, then asserts only
    the rules belonging to `chain`. Returns how many were asserted.

    Mirrors bridge.py's _run_via_pyswip: rule/8 has no chain field of
    its own (see query_engine.pl's module note), so restricting to one
    chain happens here, in Python, by filtering BEFORE assert -- exactly
    how bridge.py's run_engine() already splits chains before calling
    the Phase 2 detector once per chain.
    """
    list(prolog.query("retractall(rule(_,_,_,_,_,_,_,_))"))
    chain_rules = [r for r in rules if r.chain == chain]
    for rule in chain_rules:
        fact_str = rule.to_prolog_fact().rstrip(".")
        prolog.assertz(fact_str)
    return len(chain_rules)


# ══════════════════════════════════════════════════════════════════
# 4. Public entry points -- one per query_engine.pl predicate
# ══════════════════════════════════════════════════════════════════

def is_allowed(
    rules: list[Rule], chain: str,
    src_ip: str, dst_ip: str, protocol: str, port: int,
) -> QueryResult:
    """"Can src_ip reach dst_ip on protocol/port within this chain?""

    protocol must be one of "tcp" | "udp" | "icmp" | "any" (matches
    rule/8's own Protocol domain -- see firewall_engine.pl §1).
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        src_term = _ip_term(src_ip)
        dst_term = _ip_term(dst_ip)
        port_int = _port_int(port)

        goal = (
            f"is_allowed({src_term}, {dst_term}, {protocol}, {port_int}, Decision)"
        )
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("is_allowed", False, error="query yielded no solution")
        return QueryResult(
            "is_allowed", True,
            raw_solution={"decision": str(solutions[0]["Decision"])},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("is_allowed", False, error=f"engine error: {e}")


def reachable_from(rules: list[Rule], chain: str, src_ip: str) -> QueryResult:
    """"What can src_ip reach (via ALLOW rules) within this chain?"

    See query_engine.pl's reachable_from/2 docstring for this predicate's
    stated limitation: it lists matching ALLOW rules, it does not
    simulate first-match precedence against DENY rules for every
    possible destination/port pair. query_bridge.py passes that caveat
    through unchanged rather than silently promising more than the
    Prolog predicate actually guarantees.
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        src_term = _ip_term(src_ip)
        goal = f"reachable_from({src_term}, Dests)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("reachable_from", False, error="query yielded no solution")
        return QueryResult(
            "reachable_from", True,
            raw_solution={"destinations": solutions[0]["Dests"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("reachable_from", False, error=f"engine error: {e}")


def who_can_reach(rules: list[Rule], chain: str, dst_ip: str) -> QueryResult:
    """Mirror of reachable_from -- see that function's docstring for the
    same stated limitation (ALLOW-rule listing, not a full simulation).
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        dst_term = _ip_term(dst_ip)
        goal = f"who_can_reach({dst_term}, Sources)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("who_can_reach", False, error="query yielded no solution")
        return QueryResult(
            "who_can_reach", True,
            raw_solution={"sources": solutions[0]["Sources"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("who_can_reach", False, error=f"engine error: {e}")


def rules_matching_ip(
    rules: list[Rule], chain: str, ip: str, direction: str = "dst",
) -> QueryResult:
    """"Which rules mention this IP (as source or destination)?"
    direction must be "src" or "dst".
    """
    if direction not in ("src", "dst"):
        return QueryResult("rules_matching_ip", False, error='direction must be "src" or "dst"')
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        ip_term = _ip_term(ip)
        goal = f"rules_matching_ip({ip_term}, {direction}, Matches)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("rules_matching_ip", False, error="query yielded no solution")
        return QueryResult(
            "rules_matching_ip", True,
            raw_solution={"matches": solutions[0]["Matches"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("rules_matching_ip", False, error=f"engine error: {e}")


def why_shadowed(rules: list[Rule], chain: str, rule_id: int) -> QueryResult:
    """"Why does rule rule_id never fire?"

    Wraps firewall_engine.pl's own is_shadowed/2 (the same predicate the
    full audit report already uses) via query_engine.pl's why_shadowed/2 --
    see that predicate's docstring. Needs firewall_engine.pl consulted
    too (not just query_engine.pl / ip_subnet.pl), since why_shadowed/2
    calls into it.
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(ENGINE_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        goal = f"why_shadowed({int(rule_id)}, ShadowingIDs)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("why_shadowed", False, error="query yielded no solution")
        return QueryResult(
            "why_shadowed", True,
            raw_solution={"shadowing_ids": solutions[0]["ShadowingIDs"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("why_shadowed", False, error=f"engine error: {e}")


def is_redundant_rule(rules: list[Rule], chain: str, rule_id: int) -> QueryResult:
    """"Is rule rule_id redundant, and because of which earlier rule?"

    Wraps firewall_engine.pl's is_redundant/2 via query_engine.pl's
    is_redundant_rule/2. Needs firewall_engine.pl consulted, same as
    why_shadowed above.
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(ENGINE_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        goal = f"is_redundant_rule({int(rule_id)}, CauseIDs)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("is_redundant_rule", False, error="query yielded no solution")
        return QueryResult(
            "is_redundant_rule", True,
            raw_solution={"cause_ids": solutions[0]["CauseIDs"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("is_redundant_rule", False, error=f"engine error: {e}")


def conflicting_rules(rules: list[Rule], chain: str, rule_id: int) -> QueryResult:
    """"Which other rules does rule_id conflict with?"

    Wraps firewall_engine.pl's is_correlated/2 (checked in both pair
    orderings) via query_engine.pl's conflicting_rules/2. Needs
    firewall_engine.pl consulted, same as why_shadowed above.
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(ENGINE_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        goal = f"conflicting_rules({int(rule_id)}, ConflictingIDs)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("conflicting_rules", False, error="query yielded no solution")
        return QueryResult(
            "conflicting_rules", True,
            raw_solution={"conflicting_ids": solutions[0]["ConflictingIDs"]},
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("conflicting_rules", False, error=f"engine error: {e}")


def rule_summary(rules: list[Rule], chain: str) -> QueryResult:
    """"How many rules are there? How many allow/deny? Per protocol?"

    Pure count over query_engine.pl's rule_summary/4 -- no
    firewall_engine.pl involvement, so it does not need ENGINE_PL
    consulted (see that predicate's own docstring).
    """
    try:
        prolog = bridge._get_prolog()
        prolog.consult(SUBNET_PL)
        prolog.consult(QUERY_ENGINE_PL)
        _assert_chain(prolog, rules, chain)

        goal = "rule_summary(Total, AllowCount, DenyCount, ByProtocol)"
        solutions = list(prolog.query(goal))
        if not solutions:
            return QueryResult("rule_summary", False, error="query yielded no solution")
        sol = solutions[0]
        by_protocol = [
            (str(pair[0]), int(pair[1])) for pair in sol["ByProtocol"]
        ]
        return QueryResult(
            "rule_summary", True,
            raw_solution={
                "total": int(sol["Total"]),
                "allow_count": int(sol["AllowCount"]),
                "deny_count": int(sol["DenyCount"]),
                "by_protocol": by_protocol,
            },
            backend="pyswip",
        )
    except Exception as e:
        return QueryResult("rule_summary", False, error=f"engine error: {e}")
