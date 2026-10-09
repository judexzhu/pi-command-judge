# Complete Hard-Defer Rules Reference & Architecture

## Overview
Hard-defer rules are deterministic, zero-latency safety screens evaluated **before** any model judge call. If a command crosses any active hard line, evaluation stops in **<1ms**, returning `verdict: "defer"`. 

The command is never sent to the LLM judge and is never auto-allowed: it immediately presents a human confirmation prompt to the engineer.

Operators can configure rules per category or by rule name in `~/.pi/agent/extensions/pi-command-judge/config.json`. **Disabling a hard-defer rule does not auto-allow the command**; it delegates evaluation to the model judge ($P(\text{allow}) \ge 0.90$).

---

## Evaluation Pipeline & Normalization

Before matching against regular expressions, the engine normalizes the command line to prevent common obfuscation and evasion techniques:
1. **Quote-Aware Segmentation**: Splits compound lines across unquoted control operators (`;`, `&&`, `||`, `|`, `&`, `\n`). Operators inside single (`'...'`) or double (`"..."`) quotes are preserved as literal arguments.
2. **Transparent Wrapper Stripping**: Strips prefixes that alter how a command runs without changing what it is:
   - `env FOO=bar ...`
   - `sudo` (caught as privilege)
   - `time`, `nohup`, `nice -n ...`, `ionice`, `stdbuf`, `timeout ...`
   - `command`, `builtin`, `exec`
3. **Leading Absolute Path Normalization**: `/bin/rm`, `/usr/bin/oc`, `/usr/local/bin/kubectl` normalize to their base executable name.
4. **Alias & Quote Bypass Stripping**: `\rm`, `"rm"`, `'rm'` normalize to `rm`.

---

## Complete Category & Rule Specification

### 1. `deletion`
Destructive file and directory removals that cannot be undone.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `delete` | `rm -rf <path>`, `rmdir`, `unlink`, `shred`, `srm`, `trash`, `trash-put` | Direct deletion of workspace or system files. |
| `find-delete-or-exec` | `find . -name "*.log" -delete`<br>`find . -exec rm {} +` | Batch deletion or unconstrained command execution via `find`. |

---

### 2. `substitutions`
Dynamic shell execution constructs that obscure what commands will run at parse time.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `command-substitution` | `$(...)`, `` `...` `` | Subcommand runs before the outer command finishes parsing; output can inject arbitrary arguments. |
| `process-substitution` | `<(...)`, `>(...)` | Creates anonymous named pipes running background child processes. |
| `heredoc` | `<<EOF`, `<<- 'DELIM'` | Multiline input redirection that can pipe uninspected scripts into interpreters. |

---

### 3. `privilege`
Elevation to root, system administrator, or another user.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `privilege` | `sudo ...`, `doas ...`, `su - ...`, `pkexec ...` | Escapes workstation user boundary; can alter kernel, daemon, or OS security policy. |

---

### 4. `indirection`
Dynamic shell interpreters and argument-dispatch engines.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `shell-wrapper` | `bash -c "..."`, `sh -c "..."`, `zsh -c "..."` | Nested string execution that evades top-level command tokenization. |
| `eval-or-source` | `eval "$CMD"`, `source ./env.sh`, `. ./setup` | Evaluates raw variables as executable code or loads uncontrolled files into active shell. |
| `xargs` | `... \| xargs rm`, `xargs -I {} ...` | Passes arbitrary streams into executable parameters. |
| `parallel-runner` | `parallel ...`, `watch -n 1 ...` | Asynchronous or continuous arbitrary command execution. |

---

### 5. `gitRemote`
Irreversible local Git history destruction and remote repository mutations.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `git-destructive` | `git push` (including `--force`, `--delete`)<br>`git reset --hard`<br>`git clean -fdx`<br>`git checkout -- .`, `git restore .`<br>`git branch -D`<br>`git stash drop`, `git stash clear`<br>`git filter-branch`, `git filter-repo`<br>`git reflog expire`, `git gc --prune` | Destroys uncommitted code, discards local commits, deletes branches, or mutates remote Git servers. Safe operations like `git commit -m "fix: push bug"`, `git diff`, and `git status` pass. |
| `gh-mutation` | `gh pr create`, `gh pr merge`, `gh pr close`<br>`gh release create`, `gh api ... -X POST`<br>`gh secret set`, `gh ssh-key add` | Writes to external GitHub repositories, PRs, issues, or releases. |
| `gh-workflow-run`| `gh workflow run ci.yml` | Dispatches remote CI/CD executions. |

---

### 6. `k8s`
Mutating actions against Kubernetes or OpenShift clusters.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `kube-mutation` | `oc` / `kubectl` executing:<br>`apply`, `create`, `delete`, `patch`, `edit`, `replace`, `scale`, `rollout`, `drain`, `cordon`, `exec`, `debug`, `rsh`, `cp`, `login`, `logout` | Modifies cluster state, deletes pods/workloads, or opens interactive remote shells into pods. Read-only queries (`get`, `describe`, `logs`, `top`, `explain`) are allowed. |
| `kube-context-switch` | `kubectl config use-context ...`<br>`oc project ...` | Switches active credentials/target cluster, risking accidental execution against production. |
| `helm-mutation` | `helm install`, `upgrade`, `uninstall`, `rollback`, `push` | Deploys, modifies, or tears down Helm chart releases. |

---

### 7. `cloud`
Cloud provider infrastructure, managed service tools, and IaC deployments.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `aws-mutation` | `aws ec2 terminate-instances`, `aws s3 rm`, `aws iam create-user` | Cloud resource mutation or destruction. Read-only commands (`aws ec2 describe-instances`, `aws sts get-caller-identity`, `aws s3 ls`) are allowed. |
| `az-mutation` | `az aks delete`, `az vm start/stop`, `az deploy` | Mutates Azure cloud resources. Read queries (`az group show`, `az list`) pass. |
| `gcloud-mutation`| `gcloud compute instances delete`, `gcloud deploy` | Mutates Google Cloud infrastructure. |
| `ocm-mutation` | `ocm post ...`, `ocm patch ...`, `ocm delete ...` | Mutates OpenShift Cluster Manager managed clusters. Read queries (`ocm get`, `ocm list`, `ocm describe`) pass. |
| `rosa-mutation`| `rosa create cluster`, `rosa delete ...`, `rosa edit ...` | Mutates Red Hat OpenShift Service on AWS (ROSA). |
| `ops-tooling` | `osdctl ...`, `backplane ...` | SRE/Ops cluster operations. |
| `terraform-mutation` | `terraform apply`, `tofu destroy`, `terraform state rm` | Applies or tears down Infrastructure as Code. |
| `deploy-tools` | `ansible-playbook ...`, `pulumi up`, `argocd app sync` | Configuration management and GitOps synchronizations. |

---

### 8. `secrets`
Direct inspection, dumps, or retrieval of authentication credentials and keys.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `credential-exposure` | `cat ~/.ssh/id_rsa`<br>`grep token ~/.env`<br>`head ~/.aws/credentials`<br>`cat ~/.netrc` | Direct file read or search targeting private keys, tokens, or environment files. |
| `kube-secrets` | `oc get secrets -A`, `kubectl extract secret/...`, `oc whoami -t` | Dumps cluster secrets or authentication tokens. |
| `az-secrets` | `az keyvault secret show ...` | Dumps secrets from Azure KeyVault. |
| `aws-secrets` | `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption` | Extracts plaintext secrets from AWS Secrets Manager or SSM Parameter Store. |

---

### 9. `network`
Outbound data transfer, remote access, or arbitrary HTTP writes.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `network` | `curl ...`, `wget ...`, `ssh ...`, `scp ...`, `sftp ...`, `rsync ...`, `nc ...`, `socat ...` | Potential for data exfiltration, downloading uninspected binaries, or establishing reverse shells. |

---

### 10. `packages`
Invoking package managers that download and execute arbitrary third-party scripts.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `package-install` | `npm install <pkg>`, `pnpm add`, `yarn add`, `npx <tool>`, `pip install`, `uv pip install`, `brew install`, `apt install`, `dnf install`, `cargo install`, `go install` | Package post-install scripts (`preinstall`, `postinstall`, `build.rs`) execute arbitrary binaries on the host workstation. |

---

### 11. `database`
Direct CLI database operations that drop or wipe persistent storage.

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `database-mutation` | `psql -c "DROP DATABASE ..."`<br>`mysql -e "DROP TABLE ..."`<br>`mongosh --eval "db.dropDatabase()"`<br>`redis-cli flushall` | Irreversible destruction of local or remote databases and caches. |

---

### 12. `system`
Operating system reconfiguration, raw hardware writes, and Denial of Service (DoS).

| Rule Name | Trigger Pattern / Examples | Why It Hard-Defers |
|---|---|---|
| `system` | `systemctl stop/restart`, `kill -9`, `reboot`, `shutdown`, `crontab -r`, `mount`, `umount`, `fdisk`, `parted`, `wipefs`, `chown` | Modifies OS services, kills processes, deletes cron jobs, or modifies partition tables. |
| `raw-device-write` | `dd if=... of=/dev/sda`<br>`echo zero > /dev/nvme0n1` | Overwrites raw physical disk drives or partition sectors. |
| `fork-bomb` | `:(){ :\|:& };:` | Spawns recursive child processes until kernel PID/memory exhaustion crashes workstation. |
| `system-permissions` | `chmod -R 777 /` | Recursively opens all OS system files, breaking host access control. |
| `container-mutation` | `docker rm`, `docker system prune`, `podman run --privileged` | Destroys container data or runs privileged containers with host root capabilities. |
| `container-escape` | `docker run -v /var/run/docker.sock:...` | Exposes host Docker daemon to container, allowing container-to-host root takeover. |

---

## Static Script Screening Rules (Inspected Files)

When a command executes a local file (e.g. `python3 script.py`, `./build.sh`), the file is read safely (`readScriptSafely`: within `cwd`, $\le 64\text{ KB}$, valid text). Before invoking the model, static script rules scan the file body:

| Rule Name | Target Patterns in Script Content | Why It Hard-Defers |
|---|---|---|
| `script-delete` | `shutil.rmtree()`, `os.remove()`, `fs.rmSync()`, `rm_rf()` | Script performs file deletions. |
| `script-obfuscation` | `eval()`, `exec()`, `base64.b64decode()`, `atob()`, `Buffer.from(..., 'base64')` | Hidden or dynamically compiled code that cannot be reliably analyzed. |
| `script-network-write` | `requests.post()`, `httpx.delete()`, `urllib.request.Request(method="POST")` | Script performs external HTTP mutation calls. |
| `script-kube-mutation` | Inline `oc create`, `kubectl delete` commands | Embedded cluster mutations. |
| `script-cloud-mutation`| Inline `aws ec2 terminate-...`, `az vm delete` calls | Embedded cloud CLI mutations. |
| `script-sdk-mutation` | SDK imports (`boto3`, `@kubernetes/client-node`, `google-cloud`) calling mutation methods (`terminate_instances()`, `delete_namespaced_pod()`). | Direct API-level cloud/cluster mutations. |
| `script-shell-out` | `subprocess.run(..., shell=True)`, `child_process.execSync()` | Spawns uninspected subshells with variable command strings. |
| `script-privilege` | `sudo`, `os.setuid()` | Script requests elevated privileges. |

*Note on Script Indirection*: Variable assignments like `BRANCH=$(git rev-parse HEAD)` or `DATE=$(date)` inside local shell scripts are **not** blocked by static rules; they are passed directly to the model judge to evaluate full context.

---

## Configuration Reference

Edit `~/.pi/agent/extensions/pi-command-judge/config.json`:

```json
{
  "hardDefer": {
    "enabled": true,
    "categories": {
      "k8s": false,             // Bypasses k8s hard-defer: sent to model judge
      "packages": false,        // Bypasses package-install hard-defer: sent to model judge
      "deletion": true,         // Remains hard-deferred
      "privilege": true,
      "secrets": true,
      "cloud": true
    },
    "disabledRules": [
      "find-delete-or-exec"     // Bypasses specific rule: sent to model judge
    ]
  },
  "extraHardDefer": [
    "^make\\s+(deploy|publish)\\b" // Operator's custom regex hard-defers
  ]
}
```
