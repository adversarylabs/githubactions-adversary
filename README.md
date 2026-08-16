# GitHub Actions adversary

Reviews GitHub Actions workflows for security, supply-chain, and reliability defects.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates GitHub Actions workflow files for token authority, untrusted code paths, runner safety, action pinning, timeouts, and step wiring.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns CI configuration in this platform domain. Application code, container definitions, and infrastructure resources remain with their specialist adversaries.
