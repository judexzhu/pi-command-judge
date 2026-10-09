import { describe, expect, it } from "vitest";

import { findHardDefer, splitSegments } from "../src/hard-defer.ts";
import { detectScript, scanScript } from "../src/scripts.ts";

const MUST_DEFER: string[] = [
  // deletes and destructive git
  "rm tmp.txt",
  "rm -rf build",
  "cd src && rm -rf ../dist",
  "/bin/rm x",
  "\\rm x",
  "\"rm\" -rf x",
  "git -C ../repo push",
  "git \"push\" origin",
  "oc \"delete\" pod x",
  "FOO=1 rm x",
  "time rm x",
  "find . -name '*.log' -delete",
  "find . -type f -exec chmod 600 {} +",
  "git push origin main",
  "git push --force",
  "git reset --hard HEAD~3",
  "git clean -fdx",
  "git checkout -- .",
  "git restore src/app.ts",
  "git branch -D feature",
  "git stash drop",
  // indirection
  "sudo systemctl restart crio",
  "bash -c 'ls'",
  "sh -lc ls",
  "eval \"$CMD\"",
  "echo $(cat /etc/passwd)",
  "ls `pwd`",
  "cat <<EOF > x.sh",
  "ls | xargs rm",
  "source ./env.sh",
  // cluster mutations
  "oc delete pod foo -n openshift-monitoring",
  "oc -n openshift-ingress delete pod router-default-abc",
  "kubectl apply -f deploy.yaml",
  "oc patch clusterversion version --type merge -p '{}'",
  "oc scale deploy/x --replicas=0",
  "oc rollout restart deploy/x",
  "oc adm drain node1",
  "oc adm cordon node1",
  "oc exec -it pod/x -- sh",
  "oc debug node/ip-10-0-1-1",
  "oc rsh pod/x",
  "oc cp pod/x:/tmp/a ./a",
  "oc label node n1 foo=bar",
  "oc annotate ns x a=b",
  "oc login https://api.cluster:6443",
  "kubectl config use-context customer-prod",
  "oc get secret pull-secret -n openshift-config -o yaml",
  "kubectl get secrets -A",
  "oc extract secret/pull-secret -n openshift-config",
  "oc whoami -t",
  "kubectl create token default",
  "ocm post /api/clusters_mgmt/v1/clusters/abc/upgrade_policies",
  "ocm delete /api/x",
  "ocm backplane login abc123",
  "osdctl cluster context abc",
  "backplane session",
  "rosa delete cluster -c x",
  "rosa upgrade cluster -c x",
  "rosa edit machinepool -c x",
  // cloud
  "aws ec2 terminate-instances --instance-ids i-1",
  "aws s3 rm s3://bucket/key",
  "aws s3 cp a s3://b/a",
  "aws secretsmanager get-secret-value --secret-id x",
  "aws ssm get-parameter --name x --with-decryption",
  "aws --profile prod iam create-user --user-name x",
  "az aks delete -g rg -n c",
  "az aro update -g rg -n c",
  "az keyvault secret show --name x --vault-name v",
  "az account get-access-token",
  "gcloud compute instances delete vm1",
  // forges, network, infra, installs, system
  "gh pr create --fill",
  "gh pr merge 12",
  "gh api repos/o/r/issues -f title=x",
  "gh workflow run ci.yml",
  "curl -s https://example.com",
  "wget https://x",
  "ssh bastion",
  "scp a host:/tmp",
  "helm upgrade x chart",
  "terraform apply -auto-approve",
  "terraform destroy",
  "ansible-playbook site.yml",
  "npm install left-pad",
  "pnpm add zod",
  "npx some-tool",
  "pip install requests",
  "brew install jq",
  "kill -9 1234",
  "chmod -R 777 .",
  "chown root x",
  "docker push quay.io/x/y",
  "podman exec -it c sh",
];

const NOT_HARD: string[] = [
  "ls -la",
  "git status",
  "git diff HEAD~1",
  "git log --oneline -20",
  "git add -A",
  "git commit -m 'fix: x'",
  "git commit -m 'feat: push notifications, remove rm calls'",
  "git log --grep restore",
  "git fetch origin",
  "pnpm test",
  "pnpm run build",
  "pytest -q tests/",
  "go test ./...",
  "oc get pods -n openshift-monitoring",
  "oc describe node ip-10-0-1-1",
  "oc logs -n openshift-ingress deploy/router-default --tail=200",
  "kubectl get nodes -o wide",
  "oc get clusterversion",
  "oc get co",
  "oc adm top nodes",
  "ocm get /api/clusters_mgmt/v1/clusters/abc",
  "ocm list clusters",
  "ocm describe cluster abc",
  "rosa describe cluster -c x",
  "rosa list clusters",
  "aws ec2 describe-instances --region us-east-1",
  "aws --profile prod sts get-caller-identity",
  "aws s3 ls s3://bucket",
  "az aro show -g rg -n c",
  "az aro list -o table",
  "jq '.items[].metadata.name' pods.json",
  "rg -n 'TODO' src",
  "mkdir -p out",
  "cp a.txt b.txt",
  "mv old.md new.md",
  "chmod +x scripts/run.sh",
];

describe("splitSegments quote awareness", () => {
  it("preserves pipes inside double and single quotes", () => {
    expect(splitSegments('grep -E "foo|bar" file.txt')).toEqual(['grep -E "foo|bar" file.txt']);
    expect(splitSegments("grep -E 'foo|bar' file.txt")).toEqual(["grep -E 'foo|bar' file.txt"]);
  });

  it("preserves semicolons inside quotes", () => {
    expect(splitSegments('git log --grep="fix: auth; retry"')).toEqual(['git log --grep="fix: auth; retry"']);
  });

  it("splits unquoted operators while preserving quoted arguments", () => {
    expect(splitSegments('git status && grep -E "a|b" file.txt')).toEqual([
      "git status",
      'grep -E "a|b" file.txt',
    ]);
  });
});

describe("findHardDefer", () => {
  it.each(MUST_DEFER)("defers: %s", (cmd) => {
    expect(findHardDefer(cmd)).not.toBeNull();
  });
  it.each(NOT_HARD.filter(Boolean))("leaves to the model: %s", (cmd) => {
    expect(findHardDefer(cmd)).toBeNull();
  });
  it("applies operator regexes per segment", () => {
    expect(findHardDefer("make deploy", [/^make\s+deploy\b/])?.rule).toMatch(/^extra:/);
  });
});

describe("detectScript", () => {
  it.each([
    ["python3 scripts/report.py --since 1h", "scripts/report.py"],
    ["uv run python tools/check.py", "tools/check.py"],
    ["bash ./hack/verify.sh", "./hack/verify.sh"],
    ["./hack/verify.sh", "./hack/verify.sh"],
    ["node scripts/gen.mjs", "scripts/gen.mjs"],
    ["cd x && python -u run.py", "run.py"],
  ])("%s → %s", (cmd, path) => {
    expect(detectScript(cmd)?.path).toBe(path);
  });
  it("ignores non-script commands", () => {
    expect(detectScript("python -m pytest")).toBeNull();
    expect(detectScript("oc get pods")).toBeNull();
  });
});

describe("scanScript", () => {
  const py = { path: "x.py", interpreter: "python3" };
  const sh = { path: "x.sh", interpreter: "bash" };
  it.each([
    [py, "import shutil\nshutil.rmtree('build')"],
    [py, "import subprocess\nsubprocess.run(['oc', 'delete', 'pod', name])"],
    [py, "subprocess.run(f'oc get pods -n {ns}', shell=True)"],
    [py, "import base64\nexec(base64.b64decode(blob))"],
    [py, "import requests\nrequests.post(url, json=data)"],
    [py, "from kubernetes import client\nv1.delete_namespaced_pod(name, ns)"],
    [py, "import boto3\nec2.terminate_instances(InstanceIds=ids)"],
    [sh, "#!/bin/bash\nfor p in $(oc get pods -o name); do echo $p; done"],
    [sh, "set -e\noc get pods\noc delete pod stale"],
    [sh, "rm -f /tmp/out"],
  ])("flags %#", (ref, content) => {
    expect(scanScript(ref, content)).not.toBeNull();
  });
  it.each([
    [py, "import json\nprint(json.dumps({'a': 1}))"],
    [py, "import subprocess\nout = subprocess.run(['oc', 'get', 'pods', '-o', 'json'], capture_output=True)"],
    [sh, "#!/bin/bash\nset -euo pipefail\noc get nodes -o wide\noc get co\n# delete nothing"],
  ])("passes %#", (ref, content) => {
    expect(scanScript(ref, content)).toBeNull();
  });
});
