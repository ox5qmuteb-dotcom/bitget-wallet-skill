#!/usr/bin/env python3
"""Shared transaction policy checks (deny-by-default) for safe testable validation."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Set


class PolicyError(ValueError):
    """Raised when a transfer action violates policy."""


@dataclass
class TransferRequest:
    chain: str
    recipient: str
    amount: float
    contract: str = ""
    asset_symbol: str = ""
    calldata: str = ""
    action: str = "transfer"
    wallet_type: str = "local-key"
    gasless: bool = False
    override_7702: bool = False
    is_submit: bool = False
    preview_payload: Optional[Mapping[str, Any]] = None
    approval_token: str = ""


@dataclass
class PolicyConfig:
    enabled: bool = True
    mode: str = "preview-first"
    fail_closed: bool = True
    allowlist: Dict[str, Set[str]] = field(default_factory=dict)
    supported_assets: Dict[str, Set[str]] = field(default_factory=dict)
    disabled_assets: Set[str] = field(default_factory=set)
    allow_native_transfer: bool = False
    allow_gasless: bool = False
    allow_swap: bool = False
    allow_bridge: bool = False
    allow_social_login: bool = False
    allow_override_7702: bool = False
    allow_approve: bool = False
    allow_permit: bool = False
    per_tx_limit: float = 0.0
    daily_limit: float = 0.0
    session_limit: float = 0.0
    audit_log_path: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyConfig":
        allowlist = {
            str(chain).lower(): {_normalize_address(str(chain).lower(), str(item)) for item in items or []}
            for chain, items in (raw.get("allowlist") or {}).items()
        }
        supported_assets = {
            str(chain).lower(): {_normalize_address(str(chain).lower(), str(item)) for item in items or []}
            for chain, items in (raw.get("supported_assets") or {}).items()
        }
        disabled_assets = {
            str(item).strip().lower() for item in (raw.get("disabled_assets") or []) if str(item).strip()
        }
        return cls(
            enabled=bool(raw.get("enabled", True)),
            mode=str(raw.get("mode", "preview-first")),
            fail_closed=bool(raw.get("fail_closed", True)),
            allowlist=allowlist,
            supported_assets=supported_assets,
            disabled_assets=disabled_assets,
            allow_native_transfer=bool(raw.get("allow_native_transfer", False)),
            allow_gasless=bool(raw.get("allow_gasless", False)),
            allow_swap=bool(raw.get("allow_swap", False)),
            allow_bridge=bool(raw.get("allow_bridge", False)),
            allow_social_login=bool(raw.get("allow_social_login", False)),
            allow_override_7702=bool(raw.get("allow_override_7702", False)),
            allow_approve=bool(raw.get("allow_approve", False)),
            allow_permit=bool(raw.get("allow_permit", False)),
            per_tx_limit=float(raw.get("per_tx_limit", 0.0) or 0.0),
            daily_limit=float(raw.get("daily_limit", 0.0) or 0.0),
            session_limit=float(raw.get("session_limit", 0.0) or 0.0),
            audit_log_path=str(raw.get("audit_log_path", "")),
        )


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


def build_preview_payload(kind: str, **fields: Any) -> Dict[str, Any]:
    payload = {"kind": kind}
    for key, value in fields.items():
        if value is None:
            continue
        payload[key] = value
    return payload


def load_policy_config(policy_path: str) -> PolicyConfig:
    policy_file = Path(policy_path)
    if not policy_file.exists():
        raise PolicyError(
            f"DENY: transaction policy file not found: {policy_file}. "
            "Copy security/policy.example.json to a private local path and configure it first."
        )
    try:
        with policy_file.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"DENY: failed to load transaction policy file: {exc}") from exc
    cfg = PolicyConfig.from_mapping(raw)
    if not cfg.enabled:
        raise PolicyError("DENY: transaction policy is disabled")
    if cfg.mode != "preview-first":
        raise PolicyError("DENY: transaction policy must use preview-first mode")
    return cfg


def require_preview_approval(preview_payload: Mapping[str, Any], approval_token: str) -> None:
    if not approval_token:
        _deny("DENY: preview-first mode requires an approval token generated from the preview payload")
    expected = create_preview_approval_token(preview_payload)
    if approval_token != expected:
        _deny("DENY: approval token does not match preview payload")


def emit_preview(preview_payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "status": 0,
        "mode": "preview-only",
        "preview": preview_payload,
        "approvalToken": create_preview_approval_token(preview_payload),
    }


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


def append_audit_log(policy: PolicyConfig, payload: Mapping[str, Any]) -> None:
    if not policy.audit_log_path:
        return
    target = Path(policy.audit_log_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(sanitize_audit_log(dict(payload)), sort_keys=True) + "\n")


def validate_asset_allowed(cfg: PolicyConfig, chain: str, contract: str = "", asset_symbol: str = "") -> bool:
    normalized_chain = (chain or "").lower()
    normalized_symbol = (asset_symbol or "").strip().lower()
    normalized_contract = _normalize_address(normalized_chain, contract)
    if normalized_symbol and normalized_symbol in cfg.disabled_assets:
        _deny("DENY: asset is disabled by policy")
    if normalized_contract and normalized_contract.lower() in cfg.disabled_assets:
        _deny("DENY: asset is disabled by policy")
    supported_assets = {
        _normalize_address(normalized_chain, item) for item in cfg.supported_assets.get(normalized_chain, set())
    }
    if supported_assets and normalized_contract and normalized_contract not in supported_assets:
        _deny("DENY: asset is not enabled by policy")
    return True


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

    validate_asset_allowed(cfg, chain, req.contract, req.asset_symbol)

    if not cfg.allow_native_transfer and req.contract == "":
        _deny("DENY: native-token transfers are disabled by default")

    if req.gasless and not cfg.allow_gasless:
        _deny("DENY: gasless execution is disabled by default")

    if req.wallet_type == "social" and not cfg.allow_social_login:
        _deny("DENY: social-login execution is disabled by default")

    action = (req.action or "").lower()
    calldata = (req.calldata or "").lower()

    if action == "swap" and not cfg.allow_swap:
        _deny("DENY: swap execution is disabled by default")

    if action == "bridge" and not cfg.allow_bridge:
        _deny("DENY: bridge execution is disabled by default")

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
        require_preview_approval(req.preview_payload, req.approval_token)

    return True
