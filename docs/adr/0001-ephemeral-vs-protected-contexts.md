# 0001: Separation of Ephemeral vs Protected Contexts

## Status
Accepted

## Context
`pi-command-judge` currently defers all Kubernetes (`oc`, `kubectl`) and cloud mutations uniformly under hard-defer rules (`src/hard-defer.ts`). In development scenarios where engineers operate against local ephemeral clusters (`kind`, `minikube`, `crc`), this triggers unnecessary human prompt friction for safe, disposable operations.

## Decision
1. Maintain strict hard-defers for all unspecified or remote Kubernetes and cloud contexts.
2. In future iterations, introduce explicit context validation: if `kubectl config current-context` or target cluster is proven ephemeral (local host, non-cloud API endpoint), allow scoped operations while blocking production-targeted contexts.
3. Keep the fail-safe invariant: when context cannot be determined with certainty, defer to the engineer.

## Consequences
- No accidental mutations against customer or production environments.
- Foundation laid for future rule extensions that check active kube context without compromising production safety.
