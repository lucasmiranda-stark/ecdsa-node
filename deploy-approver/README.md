# Deploy Approver (POC)

A small FastAPI service that exists to **test the trigger** for the npm deploy
workflow ([`../.github/workflows/deploy-npm.yml`](../.github/workflows/deploy-npm.yml)).

It models a deployment-approval flow: open a `DeploymentRequest` for a commit,
collect two approvals, then `process` it — which fires a GitHub
`repository_dispatch` (`event_type: deploy`) that triggers the deploy Action.

> The production microservice already owns the real approval logic, auth and
> persistence. Here those are intentionally minimal (in-memory storage,
> name-based approvers, optional shared token). The part under test is the
> GitHub dispatch in `trigger_github_deploy`.

## Setup

```sh
cd deploy-approver
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in GH_TOKEN
```

## Configuration

| Env var              | Default                          | Purpose                                                        |
| -------------------- | -------------------------------- | -------------------------------------------------------------- |
| `GH_TOKEN`           | _(required)_                     | Token to fire the dispatch (fine-grained PAT `Contents: write`, or classic `repo` scope). |
| `GH_REPO`            | `lucasmiranda-stark/ecdsa-node`  | Target repo the dispatch is sent to.                           |
| `GH_EVENT_TYPE`      | `deploy`                         | Must match `repository_dispatch.types` in the workflow.        |
| `REQUIRED_APPROVALS` | `2`                              | Distinct approvals needed before `process` is allowed.         |
| `APPROVE_API_TOKEN`  | _(empty)_                        | Optional shared bearer token; empty = no auth (POC).           |

## Run

```sh
set -a && source .env && set +a      # export env vars
uvicorn main:app --port 8000 --reload
```

Interactive API docs: <http://localhost:8000/docs>

## End-to-end test

```sh
# 1. Open a DeploymentRequest with the approved PR's head SHA
curl -s -X POST localhost:8000/deployments \
  -H 'Content-Type: application/json' \
  -d '{"commitId":"<approved-PR-head-SHA>","pr":42}'
# -> {"id":"<id>","status":"pending", ...}

# 2. Two distinct people approve (status -> "approved" on the 2nd)
curl -s -X POST localhost:8000/deployments/<id>/approve \
  -H 'Content-Type: application/json' -d '{"approver":"alice"}'
curl -s -X POST localhost:8000/deployments/<id>/approve \
  -H 'Content-Type: application/json' -d '{"approver":"bob"}'

# 3. Process -> fires repository_dispatch -> the deploy workflow runs
curl -s -X POST localhost:8000/deployments/<id>/process
# -> {"status":"processed", ...}
```

After step 3, the run appears under the repo's **Actions** tab. The workflow
checks out `<approved-PR-head-SHA>` and publishes it to npm with provenance.

If `APPROVE_API_TOKEN` is set, add `-H "Authorization: Bearer <token>"` to every
call.
