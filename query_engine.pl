:- encoding(utf8).
% Required first directive -- matches firewall_engine.pl's own convention
% (see that file's top comment). This file has no Persian text today, but
% query_bridge.py may eventually pass Persian rule labels through error
% messages, and consulting a UTF-8 file without this directive is a
% silent-mangling trap, not a hard error -- cheaper to declare it now.

% ============================================================================
% query_engine.pl
%
% Phase 3 (NL Query) -- Read-only query predicates over rule/8
% ----------------------------------------------------------------------------
% Adds ask-a-question predicates on top of the existing, frozen
% firewall_engine.pl / ip_subnet.pl pipeline. Does NOT modify either file
% -- only reads rule/8 facts and reuses ip_subnet.pl's exported
% containment/overlap predicates, exactly like firewall_engine.pl itself.
%
% Schema reminder (authoritative version lives in firewall_engine.pl section 1):
%   rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort)
%     Action           -- allow | deny
%     Protocol         -- tcp | udp | icmp | any
%     SrcIP, DstIP     -- ip4(...)/ip6(...) terms (see ip_subnet.pl)
%     SrcPort, DstPort -- any | port(N) | port_range(Lo,Hi)
%
% NOTE ON CHAIN: rule/8 has no Chain field. bridge.py's run_engine splits
% rules by chain in PYTHON and runs the detector once per chain (see that
% file). This module follows the exact same convention: query_bridge.py
% asserts only the rules belonging to whichever chain the user picked
% before calling any predicate here, so "which chain" is a Python-side
% concern, never a Prolog argument.
%
% NOTE ON PARSING: every predicate below takes IPs as already-parsed
% ip4(...)/ip6(...) terms and ports as already-parsed any|port(N)|
% port_range(Lo,Hi) terms -- exactly like rule/8 itself. Turning a raw
% string like "10.10.25.5" into ip4(10,10,25,5,32) is done in Python by
% parser.py's existing ip_to_prolog() function, reused as-is (see
% query_bridge.py). This file does zero string parsing, keeping the same
% layering the rest of the project already uses: reasoning stays here,
% syntax stays in Python.
% ============================================================================

:- module(query_engine, [
    rules_matching_ip/3,
    is_allowed/5,
    reachable_from/2,
    who_can_reach/2,
    why_shadowed/2,
    is_redundant_rule/2,
    conflicting_rules/2,
    rule_summary/4
]).

:- use_module(ip_subnet).
:- use_module(firewall_engine).

:- dynamic   user:rule/8.
:- multifile user:rule/8.

% ----------------------------------------------------------------------------
% 1. rules_matching_ip(+IP, +Direction, -Matches)
% ----------------------------------------------------------------------------
% Every currently-asserted rule whose Direction ('src' or 'dst') range
% covers IP, returned sorted by Priority ascending (lowest = evaluated
% first) -- the order that matters when answering "which rule decides
% this", since the first element of Matches is the one that actually
% fires under first-match evaluation.
%
% Matches is a list of match(ID, Priority, Action, Protocol, SrcPort,
% DstPort) terms rather than raw rule/8 terms, so query_bridge.py never
% needs to know rule/8's exact field order to render a result table.
% ----------------------------------------------------------------------------
rules_matching_ip(IP, src, Matches) :-
    !,
    findall(
        Priority-match(ID, Priority, Action, Protocol, SrcPort, DstPort),
        ( rule(ID, Priority, Action, Protocol, RuleSrcIP, _DstIP, SrcPort, DstPort),
          ip_in_range(IP, RuleSrcIP)
        ),
        Pairs
    ),
    keysort(Pairs, SortedPairs),
    pairs_values(SortedPairs, Matches).

rules_matching_ip(IP, dst, Matches) :-
    !,
    findall(
        Priority-match(ID, Priority, Action, Protocol, SrcPort, DstPort),
        ( rule(ID, Priority, Action, Protocol, _SrcIP, RuleDstIP, SrcPort, DstPort),
          ip_in_range(IP, RuleDstIP)
        ),
        Pairs
    ),
    keysort(Pairs, SortedPairs),
    pairs_values(SortedPairs, Matches).

% ip_in_range(+IP, +RuleRange)
% True iff the single host/address IP falls inside RuleRange (which may
% itself be a /0-/32 or /0-/128 block, not necessarily a single host).
% Built directly from ip_subnet.pl's ip_range/3 -- IP is treated as a
% degenerate /32 or /128 block and we ask whether it is a subset of
% RuleRange, reusing is_subset_ip/2 exactly as every Phase 2 detector
% does, rather than duplicating interval arithmetic here.
ip_in_range(IP, RuleRange) :-
    is_subset_ip(IP, RuleRange).

% ----------------------------------------------------------------------------
% 2. is_allowed(+SrcIP, +DstIP, +Protocol, +Port, -Decision)
% ----------------------------------------------------------------------------
% Decision is the action of the FIRST (lowest-Priority) currently-asserted
% rule matching this traffic tuple, or 'default_deny' if no rule matches
% at all -- mirroring standard firewall default-deny semantics. Port is
% checked against DstPort only (the conventional "can X reach Y on port
% N" question); SrcPort is not constrained by the caller, matching how
% users actually phrase this kind of question.
% ----------------------------------------------------------------------------
is_allowed(SrcIP, DstIP, Protocol, Port, Decision) :-
    findall(
        Priority-Action,
        ( rule(_ID, Priority, Action, RuleProto, RuleSrcIP, RuleDstIP, _SrcPort, RuleDstPort),
          protocol_matches(Protocol, RuleProto),
          is_subset_ip(SrcIP, RuleSrcIP),
          is_subset_ip(DstIP, RuleDstIP),
          port_matches(Port, RuleDstPort)
        ),
        Pairs
    ),
    keysort(Pairs, Sorted),
    first_match_decision(Sorted, Decision).

first_match_decision([_Priority-Action|_], Action) :- !.
first_match_decision([], default_deny).

% protocol_matches(+QueryProto, +RuleProto)
% True iff a packet of QueryProto could match a rule written for
% RuleProto. Mirrors firewall_engine.pl's protocols_can_coexist/2
% exactly (that predicate is not exported, so re-declared here rather
% than modifying firewall_engine.pl's module export list).
protocol_matches(P, P) :- !.
protocol_matches(any, _) :- !.
protocol_matches(_, any) :- !.

% port_matches(+QueryPort, +RulePortSpec)
% True iff the single query port Port falls inside RulePortSpec (any |
% port(N) | port_range(Lo,Hi)). Built the same way ip_in_range/2 is
% built above: treat the query as a degenerate single-port spec and
% reuse is_subset_port/2 rather than hand-rolling comparison logic.
port_matches(Port, RulePortSpec) :-
    is_subset_port(port(Port), RulePortSpec).

% ----------------------------------------------------------------------------
% 3. reachable_from(+SrcIP, -Destinations)
% ----------------------------------------------------------------------------
% Every allow-decision destination reachable from SrcIP under the
% currently-asserted rule set: a list of dest(DstIP, Protocol, DstPort,
% RuleID) terms for every ALLOW rule whose SrcIP range covers SrcIP.
%
% IMPORTANT LIMITATION (state plainly, do not hide): this lists every
% ALLOW rule matching SrcIP, WITHOUT checking whether an earlier,
% higher-priority DENY rule would shadow it for the exact same traffic.
% A fully first-match-correct answer would need to run is_allowed/5 for
% every (DstIP, Protocol, Port) combination implied by each candidate
% rule -- combinatorially expensive and not what this predicate promises.
% This is a "what ALLOW rules exist for this source" report, not a
% "what will actually get through" simulator. query_bridge.py's rendered
% answer must say so explicitly rather than imply a guarantee this
% predicate does not make. (is_allowed/5 above IS the fully-correct,
% single-tuple version -- use that when the question is about one
% specific destination/port, not a broad "what can X reach" survey.)
% ----------------------------------------------------------------------------
reachable_from(SrcIP, Destinations) :-
    findall(
        dest(RuleDstIP, Protocol, DstPort, ID),
        ( rule(ID, _Priority, allow, Protocol, RuleSrcIP, RuleDstIP, _SrcPort, DstPort),
          is_subset_ip(SrcIP, RuleSrcIP)
        ),
        Destinations
    ).

% ----------------------------------------------------------------------------
% 4. who_can_reach(+DstIP, -Sources)
% ----------------------------------------------------------------------------
% Mirror of reachable_from/2: every ALLOW rule whose DstIP range covers
% DstIP, as source(SrcIP, Protocol, DstPort, RuleID) terms. Same
% limitation as reachable_from/2 above -- this is "which ALLOW rules
% target this destination", not a first-match-verified simulation.
% ----------------------------------------------------------------------------
who_can_reach(DstIP, Sources) :-
    findall(
        source(RuleSrcIP, Protocol, DstPort, ID),
        ( rule(ID, _Priority, allow, Protocol, RuleSrcIP, RuleDstIP, _SrcPort, DstPort),
          is_subset_ip(DstIP, RuleDstIP)
        ),
        Sources
    ).

% ----------------------------------------------------------------------------
% 5. why_shadowed(+RuleID, -ShadowingIDs)
% ----------------------------------------------------------------------------
% "Why does rule RuleID never fire?" ShadowingIDs is the list of every
% earlier, currently-asserted rule ID that shadows RuleID (usually zero
% or one, but findall/list-returning keeps this correct even if more
% than one earlier rule independently covers it).
%
% This does NOT reimplement shadowing detection: it calls
% firewall_engine.pl's own is_shadowed/2 (the same, frozen, tested
% predicate the full audit report uses) and simply asks "for which
% ShadowingID does is_shadowed(RuleID, ShadowingID) hold". Zero
% duplicate anomaly logic between the audit report and this query.
% ----------------------------------------------------------------------------
why_shadowed(RuleID, ShadowingIDs) :-
    findall(ShadowingID, is_shadowed(RuleID, ShadowingID), ShadowingIDs).

% ----------------------------------------------------------------------------
% 6. is_redundant_rule(+RuleID, -CauseIDs)
% ----------------------------------------------------------------------------
% "Is rule RuleID redundant, and if so because of which earlier rule?"
% CauseIDs is the list of earlier rule IDs that already cover RuleID
% with the SAME action (see firewall_engine.pl's is_redundant/2 for the
% shadowing-vs-redundancy distinction: same action here, not conflicting).
% An empty list means the rule is not redundant under this detector.
% Reuses is_redundant/2 as-is -- no new anomaly logic.
% ----------------------------------------------------------------------------
is_redundant_rule(RuleID, CauseIDs) :-
    findall(CauseID, is_redundant(RuleID, CauseID), CauseIDs).

% ----------------------------------------------------------------------------
% 7. conflicting_rules(+RuleID, -ConflictingIDs)
% ----------------------------------------------------------------------------
% "Which other rules does RuleID conflict with?" (the Correlation
% anomaly: overlapping traffic, contradictory actions, neither rule
% fully covers the other -- see firewall_engine.pl's is_correlated/2).
% ConflictingIDs lists every other currently-asserted rule ID that
% conflicts with RuleID, in either position of the (symmetric)
% is_correlated/2 pair. An empty list means no detected conflict.
% ----------------------------------------------------------------------------
conflicting_rules(RuleID, ConflictingIDs) :-
    findall(Other, correlated_with(RuleID, Other), ConflictingIDs).

% correlated_with(+RuleID, -Other)
% is_correlated/2 reports each conflicting pair once, as (ID1, ID2)
% with ID1 < ID2 (see that predicate's own doc comment). RuleID may
% legitimately appear on either side, so both orderings are tried here
% rather than assuming RuleID is always the smaller ID.
correlated_with(RuleID, Other) :- is_correlated(RuleID, Other).
correlated_with(RuleID, Other) :- is_correlated(Other, RuleID).

% ----------------------------------------------------------------------------
% 8. rule_summary(-Total, -AllowCount, -DenyCount, -ByProtocol)
% ----------------------------------------------------------------------------
% "How many rules are there? How many allow/deny? Broken down by
% protocol?" A plain count over whichever chain's rule/8 facts are
% currently asserted (query_bridge.py asserts exactly one chain before
% calling this, same convention as every predicate above). ByProtocol
% is a list of Protocol-Count pairs (e.g. tcp-12, udp-3, icmp-1, any-2),
% sorted by protocol name for a stable, deterministic display order.
%
% Pure bookkeeping over rule/8 -- no anomaly detection, no ip_subnet.pl
% call, nothing that needs firewall_engine.pl. Kept here rather than in
% firewall_engine.pl because it is a query-only convenience, not part
% of the anomaly-detection contract that file's frozen tests cover.
% ----------------------------------------------------------------------------
rule_summary(Total, AllowCount, DenyCount, ByProtocol) :-
    findall(ID, rule(ID, _, _, _, _, _, _, _), AllIDs),
    length(AllIDs, Total),
    aggregate_all(count, rule(_, _, allow, _, _, _, _, _), AllowCount),
    aggregate_all(count, rule(_, _, deny, _, _, _, _, _), DenyCount),
    findall(
        Protocol,
        rule(_, _, _, Protocol, _, _, _, _),
        AllProtocols
    ),
    sort(AllProtocols, DistinctProtocols),
    findall(
        Protocol-Count,
        ( member(Protocol, DistinctProtocols),
          aggregate_all(
              count,
              rule(_, _, _, Protocol, _, _, _, _),
              Count
          )
        ),
        ByProtocol
    ).
