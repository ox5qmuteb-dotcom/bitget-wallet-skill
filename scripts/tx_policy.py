from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_FILE = REPO_ROOT / "security" / "policy.json"
DEFAULT_POLICY_EXAMPLE_FILE = REPO_ROOT / "security" / "policy.example.json"
DEFAULT_STATE_FILE = REPO_ROOT / "audit" / "policy-state.json"
DEFAULT_AUDIT_LOG = REPO_ROOT / "audit" / "security-audit.ndjson"

EVM_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}

APPROVAL_SELECTORS = {
    "0x095ea7b3": "approve(address,uint256)",
    "0xa22cb465": "setApprovalForAll(address,bool)",
    "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0x39509351": "increaseAllowance(address,uint256)",
    "0x8fcbaf0c": "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
}

SECRET_KEYS = (
    "mnemonic",
    "private_key",
    "private-key",
    "secret",
    "appsecret",
    "signature",
    "sig",
)


class PolicyError(RuntimeError):
    pass


@dataclass
class PolicyContext:
    policy: dict
    policy_file: Path
    state_file: Path
    audit_log: Path
    session_id: str
    approval_ttl_seconds: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError(f"Unsupported type: {type(value)!r}")


def _read_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return json.loads(json.dumps(default))
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=_json_default) + "\n", encoding="utf-8")


def _normalize_chain(chain: str) -> str:
    return (chain or "").strip().lower()


def _is_all_same_case(value: str) -> bool:
    letters = [c for c in value if c.isalpha()]
    return not letters or all(c.islower() for c in letters) or all(c.isupper() for c in letters)


def normalize_evm_address(address: str) -> str:
    address = (address or "").strip()
    if not EVM_RE.match(address):
        raise PolicyError(f"Invalid EVM address format: {address!r}")
    try:
        from eth_utils import to_checksum_address
    except ModuleNotFoundError:
        if not _is_all_same_case(address[2:]):
            raise PolicyError(
                "Mixed-case EVM addresses require checksum validation support. "
                "Use lowercase/uppercase hex or install eth_utils."
            )
        return "0x" + address[2:].lower()
    checksum = to_checksum_address(address)
    if not _is_all_same_case(address[2:]) and checksum != address:
        raise PolicyError(f"Invalid EVM checksum address: {address}")
    return checksum


def _decode_base58(value: str) -> bytes:
    num = 0
    for char in value:
        if char not in BASE58_INDEX:
            raise PolicyError(f"Invalid base58 character in address: {value!r}")
        num = num * 58 + BASE58_INDEX[char]
    out = bytearray()
    while num:
        num, remainder = divmod(num, 256)
        out.append(remainder)
    out.reverse()
    leading_zeros = len(value) - len(value.lstrip("1"))
    return bytes(b"\x00" * leading_zeros + out)


def normalize_solana_address(address: str) -> str:
    address = (address or "").strip()
    raw = _decode_base58(address)
    if len(raw) != 32:
        raise PolicyError(f"Invalid Solana address length: {address!r}")
    return address


def normalize_tron_address(address: str) -> str:
    address = (address or "").strip()
    raw = _decode_base58(address)
    if len(raw) != 25 or not address.startswith("T"):
        raise PolicyError(f"Invalid Tron address format: {address!r}")
    return address


def normalize_address(chain: str, address: str) -> str:
    chain = _normalize_chain(chain)
    if chain in {"eth", "bnb", "base", "arbitrum", "matic", "morph", "op"}:
        return normalize_evm_address(address)
    if chain in {"sol", "solana"}:
        return normalize_solana_address(address)
    if chain in {"trx", "tron"}:
        return normalize_tron_address(address)
    raise PolicyError(f"Unsupported chain for address validation: {chain}")


def normalize_contract(chain: str, contract: str) -> str:
    contract = (contract or "").strip()
    if contract == "":
        return ""
    return normalize_address(chain, contract)


def _decimal(value: str, field_name: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise PolicyError(f"Invalid decimal amount for {field_name}: {value!r}") from exc
    if parsed <= 0:
        raise PolicyError(f"Amount must be greater than zero for {field_name}")
    return parsed


def _sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        clean = {}
        for key, value in obj.items():
            lower = key.lower()
            if any(secret_key in lower for secret_key in SECRET_KEYS):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = _sanitize(value)
        return clean
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


def load_policy_context(policy_file: Optional[str] = None) -> PolicyContext:
    policy_path = Path(policy_file or os.environ.get("BGW_POLICY_FILE") or DEFAULT_POLICY_FILE)
    policy = _read_json(policy_path, {"enabled": False}) if policy_path.exists() else {"enabled": False}
    state_file = Path(os.environ.get("BGW_POLICY_STATE_FILE") or DEFAULT_STATE_FILE)
    audit_log = Path(os.environ.get("BGW_AUDIT_LOG") or DEFAULT_AUDIT_LOG)
    state = _read_json(state_file, {"session_id": str(uuid.uuid4()), "approvals": {}, "totals": {"daily": {}, "session": {}}})
    if not state.get("session_id"):
        state["session_id"] = str(uuid.uuid4())
        _write_json(state_file, state)
    return PolicyContext(
        policy=policy,
        policy_file=policy_path,
        state_file=state_file,
        audit_log=audit_log,
        session_id=state["session_id"],
        approval_ttl_seconds=int(policy.get("approval_ttl_seconds", 900) or 900),
    )


def _require_enabled(ctx: PolicyContext) -> None:
    if not ctx.policy.get("enabled"):
        raise PolicyError(
            "Security policy is missing or disabled. Operations are deny-by-default. "
            f"Create {ctx.policy_file} from {DEFAULT_POLICY_EXAMPLE_FILE} and explicitly allow the intended addresses, chains, contracts, and limits."
        )


def _allowed_set(values: Iterable[str], normalizer) -> set[str]:
    normalized = set()
    for value in values or []:
        try:
            normalized.add(normalizer(value))
        except PolicyError:
            continue
    return normalized


def _match_allowed(name: str, value: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise PolicyError(f"{name} {value} is not present in the policy allowlist")


def _asset_key(chain: str, contract: str) -> str:
    normalized_contract = contract or "native"
    if isinstance(normalized_contract, str) and normalized_contract.startswith("0x"):
        normalized_contract = normalized_contract.lower()
    return f"{_normalize_chain(chain)}:{normalized_contract}"


def _get_limit_config(policy: dict, chain: str, contract: str) -> dict:
    limits = policy.get("limits") or {}
    per_asset = limits.get("per_asset") or {}
    return per_asset.get(_asset_key(chain, contract), limits.get("default") or {})


def _ensure_limit(limit_name: str, amount: Decimal, used: Decimal, limit_value: str) -> None:
    if limit_value in (None, ""):
        return
    limit = Decimal(str(limit_value))
    if amount > limit and limit_name == "per_tx":
        raise PolicyError(f"Transaction amount {amount} exceeds policy {limit_name} limit {limit}")
    if used + amount > limit and limit_name in {"daily", "session"}:
        raise PolicyError(f"Transaction would exceed policy {limit_name} limit {limit} (used {used}, requested {amount})")


def _load_state(ctx: PolicyContext) -> dict:
    return _read_json(ctx.state_file, {"session_id": ctx.session_id, "approvals": {}, "totals": {"daily": {}, "session": {}}})


def _save_state(ctx: PolicyContext, state: dict) -> None:
    state["session_id"] = ctx.session_id
    _write_json(ctx.state_file, state)


def write_audit_log(ctx: PolicyContext, intent: dict, decision: str, order_id: str = "", reason: str = "", extra: Optional[dict] = None) -> None:
    entry = {
        "timestamp": _now().isoformat(),
        "sessionId": ctx.session_id,
        "decision": decision,
        "reason": reason,
        "orderId": order_id,
        "intent": {
            "operation": intent.get("operation"),
            "walletMode": intent.get("walletMode"),
            "chain": intent.get("chain") or intent.get("fromChain"),
            "targetChain": intent.get("toChain", ""),
            "contract": intent.get("contract") or intent.get("fromContract", ""),
            "targetContract": intent.get("toContract", ""),
            "from": intent.get("from") or intent.get("fromAddress"),
            "to": intent.get("to") or intent.get("toAddress"),
            "amount": intent.get("amount") or intent.get("fromAmount"),
            "gasless": bool(intent.get("gasless", False)),
            "override7702": bool(intent.get("override7702", False)),
        },
    }
    if extra:
        entry["extra"] = _sanitize(extra)
    ctx.audit_log.parent.mkdir(parents=True, exist_ok=True)
    with ctx.audit_log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_sanitize(entry), ensure_ascii=False, default=_json_default) + "\n")


def normalize_intent(intent: dict) -> dict:
    normalized = dict(intent)
    operation = intent.get("operation")
    if operation == "transfer":
        normalized["chain"] = _normalize_chain(intent["chain"])
        normalized["from"] = normalize_address(normalized["chain"], intent["from"])
        normalized["to"] = normalize_address(normalized["chain"], intent["to"])
        normalized["contract"] = normalize_contract(normalized["chain"], intent.get("contract", ""))
        if intent.get("gaslessPayToken"):
            normalized["gaslessPayToken"] = normalize_contract(normalized["chain"], intent["gaslessPayToken"])
        normalized["amount"] = format(_decimal(intent["amount"], "amount"), "f")
    elif operation == "swap":
        normalized["fromChain"] = _normalize_chain(intent["fromChain"])
        normalized["toChain"] = _normalize_chain(intent["toChain"])
        normalized["fromAddress"] = normalize_address(normalized["fromChain"], intent["fromAddress"])
        normalized["toAddress"] = normalize_address(normalized["toChain"], intent["toAddress"])
        normalized["fromContract"] = normalize_contract(normalized["fromChain"], intent.get("fromContract", ""))
        normalized["toContract"] = normalize_contract(normalized["toChain"], intent.get("toContract", ""))
        normalized["fromAmount"] = format(_decimal(intent["fromAmount"], "fromAmount"), "f")
    else:
        raise PolicyError(f"Unsupported operation: {operation!r}")
    return normalized


def validate_intent(ctx: PolicyContext, intent: dict) -> dict:
    _require_enabled(ctx)
    normalized = normalize_intent(intent)
    policy = ctx.policy
    allowed_chains = {_normalize_chain(chain) for chain in policy.get("allowed_chains") or []}
    if normalized["operation"] == "transfer":
        if normalized["chain"] not in allowed_chains:
            raise PolicyError(f"Chain {normalized['chain']} is not allowlisted")
        _match_allowed("from address", normalized["from"], _allowed_set(policy.get("allowed_from_addresses") or [], lambda v: normalize_address(normalized["chain"], v)))
        _match_allowed("to address", normalized["to"], _allowed_set(policy.get("allowed_to_addresses") or [], lambda v: normalize_address(normalized["chain"], v)))
        if normalized["contract"]:
            _match_allowed("contract", normalized["contract"], _allowed_set(policy.get("allowed_contracts") or [], lambda v: normalize_contract(normalized["chain"], v)))
        elif not policy.get("allow_native_transfers", False):
            raise PolicyError("Native-token transfers are blocked by policy")
        if normalized.get("gaslessPayToken"):
            _match_allowed("gasless pay token", normalized["gaslessPayToken"], _allowed_set(policy.get("allowed_contracts") or [], lambda v: normalize_contract(normalized["chain"], v)))
        limits = _get_limit_config(policy, normalized["chain"], normalized["contract"])
        amount = Decimal(normalized["amount"])
    else:
        for chain_name in (normalized["fromChain"], normalized["toChain"]):
            if chain_name not in allowed_chains:
                raise PolicyError(f"Chain {chain_name} is not allowlisted")
        _match_allowed("from address", normalized["fromAddress"], _allowed_set(policy.get("allowed_from_addresses") or [], lambda v: normalize_address(normalized["fromChain"], v)))
        _match_allowed("to address", normalized["toAddress"], _allowed_set(policy.get("allowed_to_addresses") or [], lambda v: normalize_address(normalized["toChain"], v)))
        if normalized["fromContract"]:
            _match_allowed("from contract", normalized["fromContract"], _allowed_set(policy.get("allowed_contracts") or [], lambda v: normalize_contract(normalized["fromChain"], v)))
        if normalized["toContract"]:
            _match_allowed("to contract", normalized["toContract"], _allowed_set(policy.get("allowed_contracts") or [], lambda v: normalize_contract(normalized["toChain"], v)))
        limits = _get_limit_config(policy, normalized["fromChain"], normalized["fromContract"])
        amount = Decimal(normalized["fromAmount"])

    state = _load_state(ctx)
    today = _now().date().isoformat()
    asset_key = _asset_key(normalized.get("chain") or normalized.get("fromChain"), normalized.get("contract") or normalized.get("fromContract", ""))
    daily_used = Decimal(str((state.get("totals", {}).get("daily", {}).get(today, {}) or {}).get(asset_key, "0")))
    session_used = Decimal(str((state.get("totals", {}).get("session", {}) or {}).get(asset_key, "0")))
    _ensure_limit("per_tx", amount, Decimal("0"), limits.get("per_tx"))
    _ensure_limit("daily", amount, daily_used, limits.get("daily"))
    _ensure_limit("session", amount, session_used, limits.get("session"))

    if normalized.get("override7702") and not policy.get("allow_override_7702", False):
        raise PolicyError("--override-7702 is blocked by policy; enable allow_override_7702 explicitly to use it")
    return normalized


def _approval_fingerprint(intent: dict) -> str:
    payload = json.dumps(_sanitize(intent), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def issue_preview(ctx: PolicyContext, intent: dict) -> dict:
    normalized = validate_intent(ctx, intent)
    state = _load_state(ctx)
    token = _approval_fingerprint(normalized)
    state.setdefault("approvals", {})[token] = {
        "intent": normalized,
        "created_at": _now().isoformat(),
        "used": False,
    }
    _save_state(ctx, state)
    write_audit_log(ctx, normalized, decision="preview-issued", extra={"approvalToken": token})
    return {
        "status": 0,
        "mode": "preview",
        "approvalToken": token,
        "policyFile": str(ctx.policy_file),
        "intent": _sanitize(normalized),
        "warning": "Preview only. Re-run with --confirm --approval-token <token> to sign and submit the exact same request.",
    }


def require_approval(ctx: PolicyContext, intent: dict, approval_token: str) -> dict:
    normalized = validate_intent(ctx, intent)
    token = (approval_token or "").strip()
    if not token:
        raise PolicyError("Missing --approval-token. Preview is required before signing or submission.")
    state = _load_state(ctx)
    approval = (state.get("approvals") or {}).get(token)
    if not approval:
        raise PolicyError("Approval token not found. Generate a fresh preview first.")
    created_at = datetime.fromisoformat(approval["created_at"])
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if _now() - created_at > timedelta(seconds=ctx.approval_ttl_seconds):
        raise PolicyError("Approval token expired. Generate a fresh preview first.")
    if approval.get("used"):
        raise PolicyError("Approval token has already been used. Generate a fresh preview first.")
    if approval.get("intent") != normalized:
        raise PolicyError("Approval token does not match the current request. Preview and execution must be identical.")
    write_audit_log(ctx, normalized, decision="approval-verified", extra={"approvalToken": token})
    return normalized


def mark_approval_used(ctx: PolicyContext, approval_token: str) -> None:
    if not approval_token:
        return
    state = _load_state(ctx)
    approval = (state.get("approvals") or {}).get(approval_token)
    if approval:
        approval["used"] = True
        approval["used_at"] = _now().isoformat()
        _save_state(ctx, state)


def record_success(ctx: PolicyContext, intent: dict, approval_token: str, order_id: str = "") -> None:
    state = _load_state(ctx)
    today = _now().date().isoformat()
    totals = state.setdefault("totals", {})
    daily = totals.setdefault("daily", {}).setdefault(today, {})
    session = totals.setdefault("session", {})
    asset_key = _asset_key(intent.get("chain") or intent.get("fromChain"), intent.get("contract") or intent.get("fromContract", ""))
    amount = Decimal(intent.get("amount") or intent.get("fromAmount"))
    daily[asset_key] = format(Decimal(str(daily.get(asset_key, "0"))) + amount, "f")
    session[asset_key] = format(Decimal(str(session.get(asset_key, "0"))) + amount, "f")
    _save_state(ctx, state)
    mark_approval_used(ctx, approval_token)
    write_audit_log(ctx, intent, decision="submitted", order_id=order_id)


def _selector(data_hex: str) -> str:
    value = (data_hex or "0x").lower()
    return value[:10] if value.startswith("0x") and len(value) >= 10 else value


def inspect_evm_call(ctx: PolicyContext, chain: str, to_addr: str, data_hex: str, value: Any) -> None:
    policy = ctx.policy
    normalized_to = normalize_address(chain, to_addr) if to_addr else ""
    if normalized_to:
        _match_allowed("transaction target", normalized_to, _allowed_set(policy.get("allowed_contracts") or [], lambda v: normalize_contract(chain, v)))
    selector = _selector(data_hex)
    if selector in APPROVAL_SELECTORS and not policy.get("allow_approvals", False):
        raise PolicyError(f"Blocked high-risk approval/permit calldata: {APPROVAL_SELECTORS[selector]}")
    if selector in APPROVAL_SELECTORS and normalized_to not in _allowed_set(policy.get("allowed_approval_contracts") or [], lambda v: normalize_contract(chain, v)):
        raise PolicyError(f"Approval target {normalized_to} is not allowlisted")
    value_int = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value or 0)
    if value_int > 0 and (data_hex or "0x") in {"", "0x", "0X"} and not policy.get("allow_native_transfers", False):
        raise PolicyError("Native-token transfers are blocked by policy")


def inspect_swap_response(ctx: PolicyContext, intent: dict, order_data: dict) -> None:
    for tx_item in order_data.get("txs", []):
        chain = _normalize_chain((tx_item.get("chain") or intent.get("fromChain") or ""))
        derive = tx_item.get("deriveTransaction") or {}
        msgs = derive.get("msgs") or tx_item.get("msgs") or []
        if msgs and not ctx.policy.get("allow_message_signing", False):
            raise PolicyError("Hash/message signing flows are blocked by policy unless allow_message_signing is enabled")
        to_addr = derive.get("to") or tx_item.get("to") or ""
        data_hex = derive.get("data") or tx_item.get("data") or "0x"
        value = derive.get("value") or tx_item.get("value") or 0
        if chain in {"eth", "bnb", "base", "arbitrum", "matic", "morph", "op"} and to_addr:
            inspect_evm_call(ctx, chain, to_addr, data_hex, value)


def inspect_transfer_response(ctx: PolicyContext, intent: dict, transfer_data: dict) -> None:
    source = transfer_data.get("source") or {}
    source_type = source.get("type", "")
    if intent.get("gasless") and not ((transfer_data.get("noGas") or {}).get("available")):
        raise PolicyError("Gasless was requested but is unavailable. Silent fallback to a standard transfer is blocked.")
    if source_type == "evm_7702" and not ctx.policy.get("allow_eip7702_auth", False):
        raise PolicyError("EIP-7702 authorization is blocked by policy unless allow_eip7702_auth is enabled")
    if source_type in {"evm_legacy", "evm_1559", "evm_7702"}:
        evm = source.get("evm") or source.get("evm7702") or {}
        to_addr = (source.get("evm") or {}).get("to") or (source.get("evm7702") or {}).get("to") or ""
        data_hex = (source.get("evm") or {}).get("data") or "0x"
        value = (source.get("evm") or {}).get("value") or 0
        if to_addr:
            inspect_evm_call(ctx, intent["chain"], to_addr, data_hex, value)


def deny_and_log(ctx: PolicyContext, intent: dict, reason: str, order_id: str = "") -> None:
    write_audit_log(ctx, intent, decision="denied", order_id=order_id, reason=reason)
