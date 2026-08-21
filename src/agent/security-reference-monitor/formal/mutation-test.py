#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""Mutation-test the SRM TLA+ model (FR-15).

A specification that passes on the first attempt may simply be asserting
things that cannot fail. Each mutation below breaks exactly one
implementation-faithful guard in `SRM.tla`, and TLC must report a violation
of *the specific property that mutation targets*. A mutant that survives --
or that is caught only by some unrelated property -- means the targeted
property is vacuous and the model is not checking the claim it appears to.

`SRM.cfg` lists its invariants individually rather than conjoining them, so
that TLC names the one that fired; a bundled invariant would make the
per-target assertion below impossible.

Every property `SRM.cfg` asks TLC to check must be the target of at least
one mutant, and every mutant target must appear in `SRM.cfg`; both
directions are asserted after the run, so a property added to the config
without a matching mutant is a failure rather than a silent gap.

Usage:
    ./mutation-test.py          # requires tla2tools.jar (run-tlc.sh fetches it)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JAR = os.environ.get("TLA2TOOLS_JAR", os.path.join(HERE, "tla2tools.jar"))

with open(os.path.join(HERE, "SRM.tla")) as fh:
    SRC = fh.read()
with open(os.path.join(HERE, "SRM.cfg")) as fh:
    CFG = fh.read()


class AnchorError(Exception):
    """A mutation's anchor text is no longer present in SRM.tla.

    Raised instead of `assert` so that the message survives `python -O` and
    so that an edit to the model which silently disarms a mutant is reported
    as a hard failure naming the anchor, rather than as an AssertionError
    with no context.
    """


def action_body(text, header):
    """Return (start, end) offsets of the body of the action `header`."""
    try:
        start = text.index("\n" + header)
    except ValueError:
        raise AnchorError(
            "SRM.tla no longer defines %r; the mutant that targets it is "
            "disarmed. Update mutation-test.py to match the model." % header)
    return start, text.index("\n\n", start)


def drop_guard(text, header, guard):
    """Delete a single conjunct line from an action's body."""
    start, end = action_body(text, header)
    body = text[start:end]
    line = "    /\\ %s\n" % guard
    if line not in body:
        raise AnchorError(
            "guard %r is no longer a conjunct of %s; the mutant that drops "
            "it is disarmed." % (guard, header))
    return text[:start] + body.replace(line, "", 1) + text[end:]


def replace_in_action(text, header, old, new):
    start, end = action_body(text, header)
    body = text[start:end]
    mutated = body.replace(old, new)
    if mutated == body:
        raise AnchorError(
            "%s no longer contains %r; the mutant that rewrites it is "
            "disarmed." % (header, old))
    return text[:start] + mutated + text[end:]


def replace_once(text, old, new, what):
    """Whole-file single replacement with a named anchor."""
    mutated = text.replace(old, new, 1)
    if mutated == text:
        raise AnchorError(
            "SRM.tla no longer contains the %s anchor; the mutant that "
            "targets it is disarmed." % what)
    return mutated


def cfg_properties():
    """Every invariant and property SRM.cfg asks TLC to check."""
    names = set()
    section = None
    for raw in CFG.splitlines():
        line = raw.strip()
        if not line or line.startswith("\\*"):
            continue
        head = line.split()[0]
        if head in ("INVARIANTS", "PROPERTIES", "INVARIANT", "PROPERTY"):
            section = head
            continue
        if head in ("SPECIFICATION", "CONSTANTS", "CONSTANT", "INIT", "NEXT"):
            section = None
            continue
        if section and "=" not in line:
            names.add(line)
    return names


def mutants():
    """Yield (description, {properties that must fire}, mutated source)."""
    # The quarantine gate on prepare is half of what makes the monitor fail
    # closed: it stops a NEW operation being admitted after quarantine.
    yield ("quarantine gate dropped from Prepare",
           {"QuarantineAdmitsOnlyTeardown"},
           drop_guard(SRC, "Prepare(o, d, td) ==", "td \\/ ~quarantined"))

    # The gate on execute is the other half: it stops a non-teardown
    # operation prepared BEFORE the quarantine from proceeding after it.
    yield ("quarantine gate dropped from Execute",
           {"QuarantineGatesExecute"},
           drop_guard(SRC, "Execute(o, d) ==", "teardown[o] \\/ ~quarantined"))

    # Superseding relaxes the anti-clobber rule; it must stay confined to
    # teardown-on-teardown while quarantined, or it is a general clobber.
    mutated = replace_once(
        SRC,
        """       \\/ /\\ state[o] \\in {"prepared", "executed"}
          /\\ td
          /\\ teardown[o]
          /\\ quarantined
""",
        """       \\/ /\\ state[o] \\in {"prepared", "executed"}
""", "superseding clause")
    yield ("superseding not confined to teardown-while-quarantined",
           {"SupersedingIsConfined"}, mutated)

    # Retiring frees an operation id; it must not un-count the commit. The
    # rewind also decrements `commits` so that `version = commits` still
    # holds and VersionCountsAllCommits cannot fire: this mutant must be
    # caught by VersionMonotone ALONE, or that property is vacuous. The
    # rewind is clamped at zero so it cannot trip TypeOK's `\in Nat` first.
    yield ("Retire rewinds the version",
           {"VersionMonotone"},
           replace_in_action(
               SRC, "Retire(o) ==",
               "    /\\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>",
               "    /\\ version' = IF version > 0 THEN version - 1 ELSE 0\n"
               "    /\\ commits' = IF commits > 0 THEN commits - 1 ELSE 0\n"
               "    /\\ UNCHANGED <<quarantined, qcause, divergent>>"))

    # A commit that fails after the effect landed must announce the
    # divergence, since the agent reports success to the shim regardless.
    yield ("CommitFails records divergence without quarantining",
           {"DivergenceImpliesQuarantine"},
           replace_in_action(SRC, "CommitFails(o) ==",
                             '    /\\ Poison("commit-failed")',
                             "    /\\ divergent' = TRUE\n"
                             "    /\\ UNCHANGED <<quarantined, qcause>>"))

    # The digest presented to execute() must equal the authorization.
    yield ("Execute ignores the plan digest",
           {"CommittedIsPlanBound"},
           drop_guard(SRC, "Execute(o, d) ==", "d = authorized[o]"))

    # Commit must be reachable only through execute, or a plan could be
    # committed without ever having been bound.
    yield ("Commit enabled straight from prepared",
           {"CommittedIsPlanBound"},
           replace_in_action(SRC, "Commit(o) ==",
                             '    /\\ state[o] = "executed"',
                             '    /\\ state[o] \\in {"prepared", "executed"}'))

    # Quarantine must be sticky, or every fail-closed claim is temporary.
    # `qcause` and `divergent` are cleared alongside it so that neither
    # QuarantineHasCause nor DivergenceImpliesQuarantine can fire: this
    # mutant must be caught by QuarantineSticky ALONE.
    yield ("quarantine can be cleared",
           {"QuarantineSticky"},
           replace_once(
               SRC,
               "Retire(o) ==\n"
               '    /\\ state[o] = "committed"\n'
               "    /\\ Release(o)\n"
               "    /\\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>",
               "Retire(o) ==\n"
               '    /\\ state[o] = "committed"\n'
               "    /\\ Release(o)\n"
               "    /\\ quarantined' = FALSE\n"
               '    /\\ qcause\' = "none"\n'
               "    /\\ divergent' = FALSE\n"
               "    /\\ UNCHANGED <<version, commits>>",
               "Retire body"))

    # The version is what the monitor hands out as proof of the committed
    # state; a commit that lands without advancing it makes every later
    # attestation of that version a lie. `commits` still advances, so
    # VersionMonotone cannot fire (the version never decreases) -- this
    # mutant must be caught by VersionCountsAllCommits ALONE.
    yield ("Commit does not advance the version",
           {"VersionCountsAllCommits"},
           replace_in_action(SRC, "Commit(o) ==",
                             "    /\\ version' = version + 1\n",
                             "    /\\ version' = version\n"))

    # `quarantine()` records WHY it fired; the cause is what the six call
    # sites are distinguished by and what an operator sees. Losing it while
    # still latching `quarantined` leaves a monitor that is failed closed
    # for no stated reason -- QuarantineHasCause exists to forbid exactly
    # that, and nothing else can catch it.
    yield ("Poison forgets to record the cause",
           {"QuarantineHasCause"},
           replace_in_action(
               SRC, "Poison(cause) ==",
               "    /\\ qcause' = IF quarantined THEN qcause ELSE cause",
               '    /\\ qcause\' = "none"'))

    # Every cause string must be one of the six the Rust code can emit; a
    # cause outside `Causes` is precisely the drift that tests/model_drift.rs
    # guards on the Rust side. TypeOK is the only property that can see it,
    # which is also this mutant's job: to show TypeOK is not vacuous.
    yield ("Poison records a cause outside Causes",
           {"TypeOK"},
           replace_in_action(
               SRC, "Poison(cause) ==",
               "    /\\ qcause' = IF quarantined THEN qcause ELSE cause",
               '    /\\ qcause\' = "unlisted-cause"'))

    # Phase 1 is what binds an operation to the plan the policy authorized;
    # an in-flight transaction with no authorization can never be bound to
    # anything, so execute()'s digest check would be comparing against a
    # value the policy never approved.
    yield ("Prepare reserves state without an authorization",
           {"InFlightIsAuthorized"},
           replace_in_action(
               SRC, "Prepare(o, d, td) ==",
               "    /\\ authorized' = [authorized EXCEPT ![o] = d]",
               "    /\\ authorized' = [authorized EXCEPT ![o] = NoDigest]"))


def check(text):
    """Run TLC over `text`; return (verdict, violated-property-set, output)."""
    work = tempfile.mkdtemp(prefix="srm-mutation-")
    try:
        with open(os.path.join(work, "SRM.tla"), "w") as fh:
            fh.write(text)
        with open(os.path.join(work, "SRM.cfg"), "w") as fh:
            fh.write(CFG)
        proc = subprocess.run(
            ["java", "-cp", JAR, "tlc2.TLC", "-deadlock", "-nowarning",
             "-config", "SRM.cfg", "SRM.tla"],
            cwd=work, capture_output=True, text=True, timeout=900)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out = proc.stdout + proc.stderr
    if "Parsing or semantic analysis failed" in out:
        return "PARSE ERROR", set(), out
    violated = set(re.findall(
        r"^Error: (?:Invariant|Action property|Temporal property|Property) "
        r"(\S+) is violated", out, re.M))
    if violated:
        return "caught", violated, out
    if "No error has been found" in out:
        return "NOT CAUGHT", set(), out
    return "UNKNOWN", set(), out


def main():
    if not os.path.isfile(JAR):
        sys.stderr.write(
            "%s not found; run ./run-tlc.sh once to fetch it\n" % JAR)
        return 2

    verdict, _, out = check(SRC)
    print("baseline (unmutated): %s" % verdict)
    if verdict != "NOT CAUGHT":
        sys.stderr.write("the unmutated model does not check clean\n")
        sys.stderr.write(out[-3000:])
        return 1

    failures = 0
    targeted = set()
    for description, targets, text in mutants():
        targeted |= targets
        verdict, violated, out = check(text)
        # TLC halts at the first violation, so require the reported set to
        # intersect the targets rather than to contain all of them.
        hit = bool(violated & targets)
        if not hit:
            failures += 1
        print("\n[%s] %s" % ("PASS" if hit else "FAIL", description))
        print("       targets: %s" % ", ".join(sorted(targets)))
        print("       caught by: %s"
              % (", ".join(sorted(violated)) if violated else verdict))
        if not hit:
            sys.stderr.write(out[-2500:])

    # A property TLC checks but no mutant targets has never been shown to be
    # falsifiable: it may be a tautology that would pass on a model with the
    # guard it claims to protect removed. Adding a property to SRM.cfg
    # without a mutant is the drift this catches.
    untested = cfg_properties() - targeted
    if untested:
        failures += len(untested)
        print("\nFAIL: %d propert(y/ies) in SRM.cfg have no mutant proving "
              "they can fail: %s" % (len(untested), ", ".join(sorted(untested))))
    stale = targeted - cfg_properties()
    if stale:
        failures += len(stale)
        print("\nFAIL: %d mutant target(s) are not checked by SRM.cfg, so the "
              "mutant can never be caught: %s"
              % (len(stale), ", ".join(sorted(stale))))

    print("\n%d failure(s): mutants not caught by their target property, or "
          "properties with no mutant" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
