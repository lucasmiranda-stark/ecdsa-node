"""Deployment approval microservice (POC).

This is a throwaway proof-of-concept. Its only real job is to test the trigger
method for the GitHub Actions deploy workflow (``.github/workflows/deploy-npm.yml``).
The production microservice already owns the real approval logic, auth and
storage; here those are intentionally minimal (in-memory, name-based approvers,
optional shared token). The part that matters is :func:`trigger_github_deploy`.

Flow:
    1. ``POST /deployments``               open a DeploymentRequest carrying the
                                            head commit SHA of an approved-but-
                                            unmerged PR; returns a generated id,
                                            status ``pending``.
    2. ``POST /deployments/{id}/approve``  a distinct person approves; once
                                            ``REQUIRED_APPROVALS`` is reached the
                                            status flips to ``approved``.
    3. ``POST /deployments/{id}/process``  if approved, fire a GitHub
                                            ``repository_dispatch`` (event_type
                                            ``deploy``) which triggers the deploy
                                            workflow; status flips to ``processed``.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# --- Configuration (environment) -------------------------------------------

GITHUB_API = "https://api.github.com"
GH_REPO = os.getenv("GH_REPO", "lucasmiranda-stark/ecdsa-node")
GH_EVENT_TYPE = os.getenv("GH_EVENT_TYPE", "deploy")
GH_TOKEN = os.getenv("GH_TOKEN", "")
REQUIRED_APPROVALS = int(os.getenv("REQUIRED_APPROVALS", "2"))
# Optional shared bearer token protecting this API. If empty, the API is open
# (acceptable for a local POC).
APPROVE_API_TOKEN = os.getenv("APPROVE_API_TOKEN", "")

# DeploymentRequest lifecycle states.
PENDING, APPROVED, PROCESSED = "pending", "approved", "processed"


# --- Request models --------------------------------------------------------

class CreateDeployment(BaseModel):
    """Payload to open a DeploymentRequest."""

    commit_id: str = Field(..., alias="commitId")
    pr: Optional[int] = None

    model_config = {"populate_by_name": True}


class Approval(BaseModel):
    """Payload for a single approval action."""

    approver: str


# --- In-memory storage (POC) -----------------------------------------------

_DEPLOYMENTS: dict[str, dict] = {}


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _serialize(record: dict) -> dict:
    """Render an internal record as the API's camelCase JSON response shape.

    Args:
        record: The stored DeploymentRequest record.

    Returns:
        A JSON-serialisable dict using the public field names.
    """
    return {
        "id": record["id"],
        "commitId": record["commit_id"],
        "pr": record["pr"],
        "status": record["status"],
        "approvals": record["approvals"],
        "requiredApprovals": REQUIRED_APPROVALS,
        "createdAt": record["created_at"],
        "processedAt": record["processed_at"],
    }


# --- Auth (optional shared token) ------------------------------------------

def require_token(authorization: Optional[str] = Header(default=None)) -> None:
    """Enforce the shared bearer token when ``APPROVE_API_TOKEN`` is configured.

    Args:
        authorization: The incoming ``Authorization`` header, if any.

    Raises:
        HTTPException: 401 when a token is required but missing or incorrect.
    """
    if not APPROVE_API_TOKEN:
        return  # auth disabled for the POC
    if authorization != f"Bearer {APPROVE_API_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid or missing API token.")


# --- GitHub trigger (the part that matters) --------------------------------

async def trigger_github_deploy(commit_id: str, pr: Optional[int]) -> None:
    """Fire a GitHub ``repository_dispatch`` that triggers the deploy workflow.

    Sends ``event_type`` = ``GH_EVENT_TYPE`` with a ``client_payload`` carrying
    the commit SHA to publish. GitHub answers ``204 No Content`` on success.

    Args:
        commit_id: Head commit SHA to deploy (becomes ``client_payload.sha``).
        pr: PR number, for traceability only (becomes ``client_payload.pr``).

    Raises:
        HTTPException: 500 if ``GH_TOKEN`` is unset; 502 if GitHub returns
            anything other than HTTP 204.

    Example:
        >>> await trigger_github_deploy("abc123", 42)  # doctest: +SKIP
    """
    if not GH_TOKEN:
        raise HTTPException(status_code=500, detail="GH_TOKEN is not configured on the server.")

    url = f"{GITHUB_API}/repos/{GH_REPO}/dispatches"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {"event_type": GH_EVENT_TYPE, "client_payload": {"pr": pr, "sha": commit_id}}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers=headers, json=body)

    if resp.status_code != 204:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub dispatch failed ({resp.status_code}): {resp.text}",
        )


# --- Application -----------------------------------------------------------

app = FastAPI(title="Deploy Approver (POC)", version="0.1.0")


@app.get("/health")
def health() -> dict:
    """Liveness probe; echoes the configured GitHub target."""
    return {
        "status": "ok",
        "repo": GH_REPO,
        "eventType": GH_EVENT_TYPE,
        "requiredApprovals": REQUIRED_APPROVALS,
    }


@app.post("/deployments", status_code=201, dependencies=[Depends(require_token)])
def create_deployment(payload: CreateDeployment) -> dict:
    """Open a DeploymentRequest in the ``pending`` state and return its id."""
    deployment_id = uuid.uuid4().hex[:12]
    record = {
        "id": deployment_id,
        "commit_id": payload.commit_id,
        "pr": payload.pr,
        "status": PENDING,
        "approvals": [],
        "created_at": _now(),
        "processed_at": None,
    }
    _DEPLOYMENTS[deployment_id] = record
    return _serialize(record)


@app.get("/deployments", dependencies=[Depends(require_token)])
def list_deployments() -> list[dict]:
    """Return all DeploymentRequests."""
    return [_serialize(r) for r in _DEPLOYMENTS.values()]


@app.get("/deployments/{deployment_id}", dependencies=[Depends(require_token)])
def get_deployment(deployment_id: str) -> dict:
    """Return a single DeploymentRequest, or 404 if the id is unknown."""
    record = _DEPLOYMENTS.get(deployment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="DeploymentRequest not found.")
    return _serialize(record)


@app.post("/deployments/{deployment_id}/approve", dependencies=[Depends(require_token)])
def approve_deployment(deployment_id: str, payload: Approval) -> dict:
    """Register one distinct approval; reaching the quorum marks it ``approved``.

    Args:
        deployment_id: The DeploymentRequest id.
        payload: The approving person's identifier.

    Returns:
        The updated DeploymentRequest.

    Raises:
        HTTPException: 404 unknown id; 409 if already processed or if the same
            approver tries to approve twice.
    """
    record = _DEPLOYMENTS.get(deployment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="DeploymentRequest not found.")
    if record["status"] == PROCESSED:
        raise HTTPException(status_code=409, detail="DeploymentRequest already processed.")
    if payload.approver in record["approvals"]:
        raise HTTPException(status_code=409, detail=f"{payload.approver} already approved this request.")

    record["approvals"].append(payload.approver)
    if len(record["approvals"]) >= REQUIRED_APPROVALS:
        record["status"] = APPROVED
    return _serialize(record)


@app.post("/deployments/{deployment_id}/process", dependencies=[Depends(require_token)])
async def process_deployment(deployment_id: str) -> dict:
    """Trigger the GitHub deploy for an ``approved`` request and mark it processed.

    Args:
        deployment_id: The DeploymentRequest id.

    Returns:
        The updated DeploymentRequest.

    Raises:
        HTTPException: 404 unknown id; 409 if not yet approved or already
            processed; 502 if the GitHub dispatch fails.
    """
    record = _DEPLOYMENTS.get(deployment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="DeploymentRequest not found.")
    if record["status"] == PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Not enough approvals: {len(record['approvals'])}/{REQUIRED_APPROVALS}.",
        )
    if record["status"] == PROCESSED:
        raise HTTPException(status_code=409, detail="DeploymentRequest already processed.")

    await trigger_github_deploy(record["commit_id"], record["pr"])
    record["status"] = PROCESSED
    record["processed_at"] = _now()
    return _serialize(record)
