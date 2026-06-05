# Deploying to npm from GitHub Actions

This package is published to npm by a GitHub Actions workflow
(`.github/workflows/deploy-npm.yml`) that is triggered by an **external approval
flow** ("approve flux"). Authentication to npm uses **Trusted Publishing (OIDC)**,
so there are **no long-lived npm tokens** to manage.

High level:

```
approval flow ──repository_dispatch──▶ GitHub Actions workflow ──OIDC──▶ npm publish
   (2 approvals)   (event_type: deploy)    (runs from default branch)     (+ provenance)
```

---

## 1. npm configuration (one-time)

### 1.1 Bootstrap publish (required first)

npm only lets you configure a Trusted Publisher on a package that **already
exists**. So the very first version must be published manually:

```sh
npm login                      # web-based; no token created
npm publish --access public    # scoped package -> must be public on first publish
```

> `--provenance` is **not** used here — provenance only works inside a supported
> CI environment, not from a laptop. CI handles provenance automatically later.

### 1.2 Configure the Trusted Publisher

On npmjs.com → the package → **Settings → Trusted Publisher → GitHub Actions**:

| Field                | Value                          |
| -------------------- | ------------------------------ |
| Organization or user | `lucasmiranda-stark`           |
| Repository           | `ecdsa-node`                   |
| Workflow filename    | `deploy-npm.yml`               |
| Environment          | *(leave blank)*                |
| Allowed action       | **`npm publish`** only         |

Notes:

- The **workflow filename must match exactly** — a mismatch makes the publish
  step fail with an OIDC/auth error.
- Do **not** enable `npm stage publish` — that adds a second, in-npm approval
  gate, which is redundant because approval already happens in the external flow.
- After this, no `NPM_TOKEN` secret is needed and provenance is automatic.
- Requires a **public** repo, and `package.json`'s `repository.url` must match
  the repository running the workflow.

---

## 2. GitHub configuration

### 2.1 The workflow must live on the **default branch**

`repository_dispatch` (and `workflow_dispatch`) **always read the workflow file
from the default branch** (e.g. `master`) — never from a feature branch or an
arbitrary commit SHA. **Just like the PHP packages, the deploy workflow has to be
merged into the default branch before it can be triggered.**

This is a one-time setup cost, not a per-deploy one:

- The **workflow definition** (the YAML steps) always comes from the default branch.
- The **code that gets published** comes from `client_payload.sha` — the workflow
  checks out that exact commit. So you can still deploy an approved, unmerged PR's
  code; only the deploy *process* itself is pinned to the default branch.

Reading the workflow from the default branch is also a security property: a PR
author cannot rewrite the deploy steps (e.g. to steal the OIDC credential),
because their branch's copy of the workflow is never the one that runs.

### 2.2 Token for the trigger (the external caller)

The workflow itself needs **no secret** (OIDC handles publishing). Only the
*caller* that fires the dispatch needs a GitHub credential:

- **Fine-grained PAT** with **Contents: Read and write** on the repo, **or**
- **classic PAT** with the `repo` (or `public_repo`) scope.

Firing a `repository_dispatch` needs `contents: write` — it does **not** need the
`workflow` scope.

### 2.3 Workflow permissions

The workflow declares:

```yaml
permissions:
  contents: read     # checkout the approved commit
  id-token: write    # Trusted Publishing (OIDC) + automatic provenance
```

### 2.4 Gotcha: pushing the workflow file

Pushing a commit that touches `.github/workflows/**` over an HTTPS remote using a
`gh`/OAuth token fails (`refusing to allow an OAuth App to create or update
workflow ... without 'workflow' scope`). Push over **SSH**, or add the scope with
`gh auth refresh -h github.com -s workflow`.

---

## 3. Triggering the deploy

The trigger is a single GitHub REST call: `POST /repos/{owner}/{repo}/dispatches`
with `event_type: deploy` and a `client_payload` carrying the **head commit SHA**
of the approved PR.

### 3.1 Minimal trigger (curl)

```sh
curl -X POST https://api.github.com/repos/lucasmiranda-stark/ecdsa-node/dispatches \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -d '{"event_type":"deploy","client_payload":{"pr":2,"sha":"<approved-PR-head-SHA>"}}'
# success: HTTP 204 No Content
```

Or with the `gh` CLI:

```sh
echo '{"event_type":"deploy","client_payload":{"pr":2,"sha":"<sha>"}}' \
  | gh api -X POST repos/lucasmiranda-stark/ecdsa-node/dispatches --input -
```

### 3.2 The trigger inside the approval service

In the approval service, the deploy is fired by the `process` step once a
DeploymentRequest has the required approvals (see `deploy-approver/main.py`):

```python
import httpx
from fastapi import HTTPException

async def trigger_github_deploy(commit_id: str, pr: int | None) -> None:
    """Fire a repository_dispatch that triggers the deploy workflow."""
    url = f"https://api.github.com/repos/{GH_REPO}/dispatches"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {"event_type": GH_EVENT_TYPE, "client_payload": {"pr": pr, "sha": commit_id}}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers=headers, json=body)

    if resp.status_code != 204:            # 204 No Content == accepted
        raise HTTPException(status_code=502, detail=f"GitHub dispatch failed: {resp.text}")
```

### 3.3 End-to-end via the approval service

```sh
# open the request with the approved commit, approve x2, then process
ID=$(curl -s -X POST localhost:8000/deployments \
       -H 'Content-Type: application/json' \
       -d '{"commitId":"<sha>","pr":2}' \
     | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
curl -s -X POST localhost:8000/deployments/$ID/approve -H 'Content-Type: application/json' -d '{"approver":"alice"}'
curl -s -X POST localhost:8000/deployments/$ID/approve -H 'Content-Type: application/json' -d '{"approver":"bob"}'
curl -s -X POST localhost:8000/deployments/$ID/process    # -> fires the dispatch above
```

---

## 4. What the workflow does

On `repository_dispatch` (`event_type: deploy`) the workflow:

1. Validates that `client_payload.sha` was provided (fails fast otherwise).
2. Checks out that exact commit (`actions/checkout@v6`).
3. Sets up Node 22 (`actions/setup-node@v6`) and upgrades to `npm@latest`
   (Trusted Publishing needs npm ≥ 11.5.1 / Node ≥ 22.14).
4. Runs `npm ci`.
5. Runs `npm publish --provenance` — authenticated via OIDC (no token), with a
   signed provenance attestation generated automatically.

---

## 5. Checklist

- [ ] Package bootstrap-published once (so it exists on npm).
- [ ] Trusted Publisher configured (repo + `deploy-npm.yml`, action `npm publish`).
- [ ] `package.json` `repository.url` points at this repo; repo is public.
- [ ] Deploy workflow merged to the **default branch**.
- [ ] Caller has a token with `contents: write` to fire the dispatch.
- [ ] The PR being deployed bumps `version` (npm rejects a duplicate version).
