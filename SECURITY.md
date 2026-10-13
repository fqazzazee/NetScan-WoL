# Security policy — NetScan-WoL

## Supported versions

Only the latest release gets security fixes.

## Reporting a vulnerability

Do not open a public issue.

Use [private vulnerability reporting](https://github.com/fqazzazee/NetScan-WoL/security/advisories/new),
or email fadi.qazzazee@gmail.com with the details and, if you have one, a proof of
concept.

Expect an acknowledgment within 72 hours and an assessment within a week. If a fix is
warranted, you will get the timeline and credit in the release notes unless you would
rather not be named.

## Scope

**In scope:** the code in this repository, its default configuration, and its release
artifacts. Since it listens on the network, authentication bypass, agent enrollment
weaknesses, injection in the web dashboard, and input that crashes or hangs a service
are all worth reporting.

**Out of scope:** vulnerabilities in dependencies without a working exploit path through
this project, and anything that requires an attacker to already have the privileges the
issue would grant.

## Operational context

This project runs in or adjacent to operational technology environments, where the usual
tradeoffs shift: availability outranks confidentiality, patch windows are measured in
months, and a crash can have physical consequences. Report anything that could cause the
process to hang, flood a network segment, or write to a device unexpectedly — those matter
here even when they would be low severity elsewhere.
