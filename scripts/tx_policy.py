#!/usr/bin/env python3
"""Local transfer policy checks (deny-by-default) for safe testable validation."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Set


class PolicyError(ValueError):
    """Raised when a transfer action violates policy."""


@dataclass
class TransferRequest:
    chain: str
    recipient: str
    amount: float
    contract: str = ""
    calldata: str = ""
    action: str = "transfer"
    override_7702: bool = False
    is_submit: bool = False
    preview_payload: Optional[Mapping[str, Any]] = None
    approval_token: str = ""


@dataclass
class PolicyConfig:
    allowlist: Dict[str, Set[str]] = field(default_factory=dict)
    allow_native_transfer: bool = False
    allow_override_7702: bool = False
    allow_approve: bool = False
    allow_permit: bool = False
    per_tx_limit: float = 0.0
    daily_limit: float = 0.0
    session_limit: float = 0.0


def _normalize_address(chain: str, address: str) -> str:
    if not isinstance(address, str):
        return ""
    return address.lower() if chain != "sol" else address


def _deny(msg: str) -> None:
    raise PolicyError(msg)


def create_preview_approval_token(preview_payload: Mapping[str, Any], *, secret: str = "preview") -> str:
    canonical = json.dumps(preview_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{secret}:{canonical}".encode("utf-8")).hexdigest()
    return f"pvw_{digest}"


def sanitize_audit_log(payload: Any) -> Any:
    sensitive = {
        "mnemonic",
        "private_key",
        "privatekey",
        "seed",
        "seedphrase",
        "signature",
        "sig",
    }
    if isinstance(payload, dict):
        redacted: Dict[str, Any] = {}
        for key, value in payload.items():
            normalized_key = key.replace("-", "").replace("_", "").lower()
            if normalized_key in sensitive:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = sanitize_audit_log(value)
        return redacted
    if isinstance(payload, list):
        return [sanitize_audit_log(item) for item in payload]
    return payload


def evaluate_transfer(
    req: TransferRequest,
    cfg: PolicyConfig,
    *,
    daily_spent: float = 0.0,
    session_spent: float = 0.0,
) -> bool:
    chain = (req.chain or "").lower()
    if chain not in cfg.allowlist:
        _deny("DENY: chain is not allowlisted")

    recipient = _normalize_address(chain, req.recipient)
    allowlisted = {_normalize_address(chain, item) for item in cfg.allowlist.get(chain, set())}
    if recipient not in allowlisted:
        _deny("DENY: recipient is not allowlisted")

    if req.amount <= 0:
        _deny("DENY: amount must be positive")

    if cfg.per_tx_limit > 0 and req.amount > cfg.per_tx_limit:
        _deny("DENY: amount exceeds per-transaction limit")

    if cfg.daily_limit > 0 and daily_spent + req.amount > cfg.daily_limit:
        _deny("DENY: amount exceeds daily limit")

    if cfg.session_limit > 0 and session_spent + req.amount > cfg.session_limit:
        _deny("DENY: amount exceeds session limit")

    if not cfg.allow_native_transfer and req.contract == "":
        _deny("DENY: native-token transfers are disabled by default")

    action = (req.action or "").lower()
    calldata = (req.calldata or "").lower()

    if not cfg.allow_approve and (action == "approve" or calldata.startswith("0x095ea7b3")):
        _deny("DENY: approve is disabled by default")

    permit_selectors = ("0xd505accf", "0x8fcbaf0c")
    if not cfg.allow_permit and (action == "permit" or any(calldata.startswith(sig) for sig in permit_selectors)):
        _deny("DENY: permit is disabled by default")

    if req.override_7702 and not cfg.allow_override_7702:
        _deny("DENY: --override-7702 is disabled by default")

    if req.is_submit:
        if not req.preview_payload:
            _deny("DENY: submit/send requires explicit preview payload")
        if not req.approval_token:
            _deny("DENY: submit/send requires explicit approval token")
        expected = create_preview_approval_token(req.preview_payload)
        if req.approval_token != expected:
            _deny("DENY: approval token does not match preview payload")

    return True
