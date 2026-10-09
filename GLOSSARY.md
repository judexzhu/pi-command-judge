# GLOSSARY

### Command Judge
The automated authorization link reviewing residual bash commands and scripts before falling back to manual engineer confirmation.

### Ephemeral Context
A local or throwaway environment (such as `kind`, `minikube`, `crc`, or dedicated scratch namespaces like `test-*`) where automated agent mutations cause no production impact and can be rebuilt deterministically.

### Protected Context
Any customer-facing, shared, staging, or production infrastructure (e.g. ROSA HCP, ARO, OSD clusters, production AWS/Azure accounts, cluster-admin contexts) where mutations must require manual human confirmation.

### Hard Defer
An immediate, zero-latency refusal to auto-allow a command, triggered by deterministic static rules (deletes, credential access, external mutations, indirection) without invoking the evaluation model.

### Fast Allow
A deterministic, low-latency (<1ms) auto-allow for safe read-only queries (e.g. `ls`, `git status`, `git diff`, `pwd`) evaluated before network model calls.

### Model Allow
An automated approval granted only after an internal model evaluates the command/script, confirms safe effects, and passes confidence threshold $P(\text{allow}) \ge 0.90$.

### Judge Protocol Adapter
A wire-protocol adapter in the Judge Client isolating transport payload construction, structured output schema flags, and logprob extraction across differing model provider protocols (e.g. `openai-completions` and `openai-responses`).

