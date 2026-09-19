#!/usr/bin/env python3
"""Read-only wallet monitoring with pluggable providers and safe config handling."""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
import os
from threading import RLock
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import parse_qs, urlparse

import requests


SENSITIVE_CONFIG_KEYS = {
    "privatekey",
    "privatekeyfile",
    "mnemonic",
    "seed",
    "seedphrase",
    "password",
    "passphrase",
    "secret",
    "apisecret",
    "secretkey",
    "appsecret",
}
SENSITIVE_LOG_KEYS = SENSITIVE_CONFIG_KEYS | {
    "authorization",
    "accesstoken",
    "refreshtoken",
    "signature",
    "sig",
}
EVM_CHAINS = {"eth", "ethereum", "base", "bnb", "bsc", "arbitrum", "arb", "optimism", "op", "polygon", "matic"}
SOLANA_CHAINS = {"sol", "solana"}
BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BASE58_INDEX = {char: index for index, char in enumerate("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")}
BITGET_BASE_URL = "https://copenapi.bgwapi.io"


class MonitoringError(ValueError):
    """Base monitoring error."""


class ConfigError(MonitoringError):
    """Raised for invalid monitoring configuration."""


class ProviderError(MonitoringError):
    """Raised when a provider cannot return monitoring data."""


class RetryableProviderError(ProviderError):
    """Raised for transient provider failures."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_datetime(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        raise ConfigError(f"invalid datetime value: {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigError(f"invalid ISO datetime: {value}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def format_iso_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_decimal(value: Any, *, field_name: str = "value") -> Decimal:
    if isinstance(value, Decimal):
        candidate = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigError(f"{field_name} must be finite")
        candidate = repr(value)
    elif isinstance(value, int):
        candidate = str(value)
    elif isinstance(value, str):
        candidate = value.strip().replace(",", "").replace("_", "")
    else:
        raise ConfigError(f"{field_name} must be a string, int, or Decimal")
    if candidate == "":
        raise ConfigError(f"{field_name} must not be empty")
    if len(candidate) > 128:
        raise ConfigError(f"{field_name} is too large to parse safely")
    with localcontext() as ctx:
        ctx.prec = 78
        try:
            parsed = Decimal(candidate)
        except InvalidOperation as exc:
            raise ConfigError(f"{field_name} is not a valid decimal: {value}") from exc
    if not parsed.is_finite():
        raise ConfigError(f"{field_name} must be finite")
    return parsed


def parse_non_negative_int(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"{field_name} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        raise ConfigError(f"{field_name} must be an integer")
    if parsed < 0:
        raise ConfigError(f"{field_name} must be zero or greater")
    return parsed


def quantize_decimal(value: Decimal, decimals: int) -> Decimal:
    scale = Decimal(10) ** max(decimals, 0)
    return value / scale


def decimal_to_str(value: Optional[Decimal]) -> Optional[str]:
    return None if value is None else format(value, "f")


def normalize_chain(chain: str) -> str:
    return (chain or "").strip().lower()


def validate_public_address(chain: str, address: str) -> bool:
    normalized_chain = normalize_chain(chain)
    candidate = (address or "").strip()
    if normalized_chain in EVM_CHAINS:
        return len(candidate) == 42 and candidate.startswith("0x") and all(ch in "0123456789abcdefABCDEF" for ch in candidate[2:])
    if normalized_chain in SOLANA_CHAINS:
        return _is_valid_solana_public_key(candidate)
    return bool(candidate)


def _is_valid_solana_public_key(candidate: str) -> bool:
    if not candidate or any(ch not in BASE58_ALPHABET for ch in candidate):
        return False
    number = 0
    for char in candidate:
        number = number * 58 + BASE58_INDEX[char]
    decoded = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    leading_zeroes = len(candidate) - len(candidate.lstrip("1"))
    full = (b"\x00" * leading_zeroes) + (b"" if number == 0 and leading_zeroes else decoded)
    return len(full) == 32


def _normalize_key(name: str) -> str:
    return name.replace("-", "").replace("_", "").strip().lower()


def redact_sensitive_data(payload: Any) -> Any:
    if isinstance(payload, dict):
        result: Dict[str, Any] = {}
        for key, value in payload.items():
            normalized = _normalize_key(key)
            if normalized in SENSITIVE_LOG_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_sensitive_data(value)
        return result
    if isinstance(payload, list):
        return [redact_sensitive_data(item) for item in payload]
    return payload


def ensure_no_plaintext_secrets(payload: Any, *, path: str = "config") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized = _normalize_key(key)
            lowered_key = key.strip().lower()
            if lowered_key.endswith(("_env", "_env_var", "_secret_name")):
                pass
            elif normalized in SENSITIVE_CONFIG_KEYS and value not in (None, "", []):
                raise ConfigError(f"{path}.{key} stores a sensitive secret; use environment variables or a secret manager reference instead")
            ensure_no_plaintext_secrets(value, path=f"{path}.{key}")
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            ensure_no_plaintext_secrets(item, path=f"{path}[{index}]")


def emit_log(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **redact_sensitive_data(fields), "timestamp": format_iso_datetime(utcnow())}
    logger.log(level, json.dumps(payload, ensure_ascii=False, sort_keys=True))


@dataclass
class AlertRuleConfig:
    inactivity_seconds: Optional[int] = None
    min_balance: Optional[Decimal] = None
    max_balance: Optional[Decimal] = None
    large_transaction_value: Optional[Decimal] = None
    large_value_threshold: Optional[Decimal] = None

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "AlertRuleConfig":
        data = data or {}
        def _non_negative_decimal(field: str) -> Optional[Decimal]:
            raw = data.get(field)
            if raw is None:
                return None
            parsed = parse_decimal(raw, field_name=field)
            if parsed < 0:
                raise ConfigError(f"{field} must be zero or greater")
            return parsed

        inactivity_seconds = parse_non_negative_int(data["inactivity_seconds"], field_name="inactivity_seconds") if data.get("inactivity_seconds") is not None else None
        return cls(
            inactivity_seconds=inactivity_seconds,
            min_balance=_non_negative_decimal("min_balance"),
            max_balance=_non_negative_decimal("max_balance"),
            large_transaction_value=_non_negative_decimal("large_transaction_value"),
            large_value_threshold=_non_negative_decimal("large_value_threshold"),
        )

    def merged_with(self, override: "AlertRuleConfig") -> "AlertRuleConfig":
        return AlertRuleConfig(
            inactivity_seconds=override.inactivity_seconds if override.inactivity_seconds is not None else self.inactivity_seconds,
            min_balance=override.min_balance if override.min_balance is not None else self.min_balance,
            max_balance=override.max_balance if override.max_balance is not None else self.max_balance,
            large_transaction_value=override.large_transaction_value if override.large_transaction_value is not None else self.large_transaction_value,
            large_value_threshold=override.large_value_threshold if override.large_value_threshold is not None else self.large_value_threshold,
        )


@dataclass
class ProviderConfig:
    name: str
    type: str
    network: str = ""
    chain: str = ""
    rpc_url: str = ""
    rpc_url_env: str = ""
    base_url: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    retries: int = 2

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ProviderConfig":
        name = (data.get("name") or "").strip()
        kind = (data.get("type") or "").strip()
        if not name or not kind:
            raise ConfigError("each provider needs name and type")
        try:
            timeout_seconds = float(data.get("timeout_seconds", 10.0))
        except (TypeError, ValueError) as exc:
            raise ConfigError("timeout_seconds must be a number greater than zero") from exc
        retries = parse_non_negative_int(data.get("retries", 2), field_name="retries")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ConfigError("timeout_seconds must be greater than zero")
        return cls(
            name=name,
            type=kind,
            network=(data.get("network") or "").strip(),
            chain=normalize_chain(data.get("chain") or ""),
            rpc_url=(data.get("rpc_url") or "").strip(),
            rpc_url_env=(data.get("rpc_url_env") or "").strip(),
            base_url=(data.get("base_url") or "").strip(),
            options=dict(data.get("options") or {}),
            timeout_seconds=timeout_seconds,
            retries=retries,
        )

    def endpoint(self) -> str:
        if self.rpc_url_env:
            value = (os.environ.get(self.rpc_url_env) or "").strip()
            if not value:
                raise ConfigError(f"provider {self.name} requires env var {self.rpc_url_env}")
            return value
        if self.rpc_url:
            return self.rpc_url
        if self.base_url:
            return self.base_url
        return ""


@dataclass
class WalletAssetConfig:
    name: str
    provider: str
    token: str
    asset_type: str = "crypto"
    network: str = ""
    chain: str = ""
    address: str = ""
    identifier: str = ""
    contract: str = ""
    price_provider: str = ""
    quote_currency: str = "USD"
    alerts: AlertRuleConfig = field(default_factory=AlertRuleConfig)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def symbol(self) -> str:
        return self.token

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "WalletAssetConfig":
        required = ["name", "provider"]
        missing = [item for item in required if not data.get(item)]
        if missing:
            raise ConfigError(f"wallet entry missing required fields: {', '.join(missing)}")
        asset_type = str(
            data.get("asset_type") or ("crypto" if data.get("chain") or data.get("address") or data.get("contract") else "asset")
        ).strip().lower()
        symbol = str(data.get("symbol") or data.get("token") or "").strip()
        if not symbol:
            raise ConfigError("wallet entry missing required field: symbol")
        chain = normalize_chain(str(data.get("chain") or ""))
        address = str(data.get("address") or "").strip()
        identifier = str(data.get("identifier") or address or symbol).strip()
        if asset_type == "crypto":
            required_crypto = [item for item in ("network", "chain", "address") if not data.get(item)]
            if required_crypto:
                raise ConfigError(f"crypto asset entry missing required fields: {', '.join(required_crypto)}")
            if not validate_public_address(chain, address):
                raise ConfigError(f"invalid public address for {chain}: {address}")
        contract = str(data.get("contract") or "").strip()
        if contract and chain not in EVM_CHAINS and chain not in SOLANA_CHAINS:
            raise ConfigError(f"contracts are only supported for EVM and Solana chains, got: {chain}")
        if contract and not validate_public_address(chain, contract):
            raise ConfigError(f"invalid contract address for {chain}: {contract}")
        return cls(
            name=str(data["name"]).strip(),
            provider=str(data["provider"]).strip(),
            token=symbol,
            asset_type=asset_type,
            network=str(data.get("network") or asset_type.upper()).strip(),
            chain=chain,
            address=address,
            identifier=identifier,
            contract=contract,
            price_provider=str(data.get("price_provider") or "").strip(),
            quote_currency=str(data.get("quote_currency") or "USD").strip().upper(),
            alerts=AlertRuleConfig.from_mapping(data.get("alerts")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class MonitorConfig:
    providers: List[ProviderConfig]
    wallets: List[WalletAssetConfig]
    default_alerts: AlertRuleConfig = field(default_factory=AlertRuleConfig)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MonitorConfig":
        ensure_no_plaintext_secrets(data)
        providers = [ProviderConfig.from_mapping(item) for item in data.get("providers", [])]
        targets_raw = data.get("assets")
        if targets_raw is None:
            targets_raw = data.get("wallets", [])
        wallets = [WalletAssetConfig.from_mapping(item) for item in targets_raw]
        if not providers:
            raise ConfigError("monitoring config requires at least one provider")
        if not wallets:
            raise ConfigError("monitoring config requires at least one asset entry")
        return cls(
            providers=providers,
            wallets=wallets,
            default_alerts=AlertRuleConfig.from_mapping(data.get("default_alerts")),
        )

    @classmethod
    def load(cls, path: str) -> "MonitorConfig":
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_mapping(data)


@dataclass
class MonitoringSnapshot:
    name: str
    token: str
    network: str
    chain: str
    provider: str
    address: Optional[str]
    balance: Decimal
    asset_type: str = "crypto"
    identifier: str = ""
    quote_currency: str = "USD"
    approximate_value: Optional[Decimal] = None
    last_activity_at: Optional[datetime] = None
    last_transaction_hash: Optional[str] = None
    last_transaction_value: Optional[Decimal] = None
    inactivity_seconds: Optional[int] = None
    last_updated_at: datetime = field(default_factory=utcnow)
    recent_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def symbol(self) -> str:
        return self.token

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "asset_type": self.asset_type,
            "symbol": self.token,
            "token": self.token,
            "identifier": self.identifier,
            "network": self.network,
            "chain": self.chain,
            "address": self.address,
            "provider": self.provider,
            "balance": decimal_to_str(self.balance),
            "quote_currency": self.quote_currency,
            "approximate_value": decimal_to_str(self.approximate_value),
            "last_activity_at": format_iso_datetime(self.last_activity_at),
            "last_transaction_hash": self.last_transaction_hash,
            "last_transaction_value": decimal_to_str(self.last_transaction_value),
            "inactivity_seconds": self.inactivity_seconds,
            "last_updated_at": format_iso_datetime(self.last_updated_at),
            "recent_history": self.recent_history,
            "metadata": self.metadata,
        }


@dataclass
class MonitoringAlert:
    severity: str
    rule: str
    wallet: str
    message: str
    observed_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "wallet": self.wallet,
            "asset": self.wallet,
            "message": self.message,
            "observed_value": self.observed_value,
        }


class HttpTransport:
    def __init__(self, *, timeout_seconds: float = 10.0, retries: int = 2, session: Optional[requests.Session] = None):
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.session = session or requests.Session()

    def request_json(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        attempts = self.retries + 1
        last_error: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=json_body,
                    headers=dict(headers or {}),
                    timeout=self.timeout_seconds,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise RetryableProviderError(f"http {response.status_code}: {response.text[:200]}")
                if response.status_code >= 400:
                    raise ProviderError(f"http {response.status_code}: {response.text[:200]}")
                try:
                    return response.json()
                except ValueError as exc:
                    raise ProviderError(f"invalid JSON response from {url}") from exc
            except RetryableProviderError as exc:
                last_error = exc
            except requests.Timeout as exc:
                last_error = RetryableProviderError(f"timeout calling {url}")  # type: ignore[assignment]
            except requests.RequestException as exc:
                last_error = RetryableProviderError(str(exc))  # type: ignore[assignment]
            if attempt < attempts - 1:
                time.sleep(min(0.25 * (2 ** attempt), 1.0))
        raise ProviderError(str(last_error) if last_error else f"request failed for {url}")


class ProviderAdapter(ABC):
    def __init__(self, config: ProviderConfig, transport: Optional[HttpTransport] = None):
        self.config = config
        self.transport = transport or HttpTransport(timeout_seconds=config.timeout_seconds, retries=config.retries)

    @abstractmethod
    def fetch_wallet_asset(self, target: WalletAssetConfig) -> MonitoringSnapshot:
        raise NotImplementedError

    def fetch_price(self, target: WalletAssetConfig) -> Optional[Decimal]:
        return None

    def healthcheck(self) -> Dict[str, Any]:
        return {"provider": self.config.name, "status": "ok", "type": self.config.type}


def _to_hex_quantity(value: str) -> int:
    return int(value, 16) if value.startswith("0x") else int(value)


class StaticProviderAdapter(ProviderAdapter):
    def fetch_wallet_asset(self, target: WalletAssetConfig) -> MonitoringSnapshot:
        snapshots = self.config.options.get("snapshots") or {}
        item = snapshots.get(_target_lookup_key(target)) or snapshots.get(target.identifier) or snapshots.get(target.name)
        if not isinstance(item, dict):
            raise ProviderError(f"static snapshot not found for {target.name}")
        snapshot = MonitoringSnapshot(
            name=target.name,
            token=target.token,
            network=target.network,
            chain=target.chain,
            provider=self.config.name,
            address=target.address or None,
            balance=parse_decimal(item.get("balance", "0"), field_name="balance"),
            asset_type=target.asset_type,
            identifier=target.identifier,
            quote_currency=str(item.get("quote_currency") or target.quote_currency).upper(),
            approximate_value=parse_decimal(item["approximate_value"], field_name="approximate_value") if item.get("approximate_value") is not None else None,
            last_activity_at=parse_iso_datetime(item.get("last_activity_at")),
            last_transaction_hash=item.get("last_transaction_hash"),
            last_transaction_value=parse_decimal(item["last_transaction_value"], field_name="last_transaction_value") if item.get("last_transaction_value") is not None else None,
            recent_history=_normalize_history_points(item.get("recent_history"), quote_currency=str(item.get("quote_currency") or target.quote_currency).upper()),
            metadata=dict(item.get("metadata") or {}),
        )
        if snapshot.last_activity_at:
            snapshot.inactivity_seconds = int((utcnow() - snapshot.last_activity_at).total_seconds())
        return snapshot

    def fetch_price(self, target: WalletAssetConfig) -> Optional[Decimal]:
        prices = self.config.options.get("prices") or {}
        raw = prices.get(_target_lookup_key(target)) or prices.get(target.name)
        if raw is None:
            return None
        return parse_decimal(raw, field_name="price")


class EvmRpcProviderAdapter(ProviderAdapter):
    def _rpc(self, method: str, params: List[Any]) -> Any:
        endpoint = self.config.endpoint()
        if not endpoint:
            raise ConfigError(f"provider {self.config.name} has no rpc endpoint")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        result = self.transport.request_json("POST", endpoint, json_body=payload)
        if "error" in result:
            raise ProviderError(f"{self.config.name} {method} failed: {result['error']}")
        return result.get("result")

    def fetch_wallet_asset(self, target: WalletAssetConfig) -> MonitoringSnapshot:
        if normalize_chain(target.chain) not in EVM_CHAINS:
            raise ProviderError(f"{self.config.name} does not support non-EVM chain {target.chain}")
        if target.contract:
            decimals = target.metadata.get("decimals")
            if decimals is None:
                decimals_raw = self._rpc("eth_call", [{"to": target.contract, "data": "0x313ce567"}, "latest"])
                decimals = _to_hex_quantity(decimals_raw)
            balance_call = "0x70a08231" + target.address.lower().replace("0x", "").rjust(64, "0")
            balance_raw = self._rpc("eth_call", [{"to": target.contract, "data": balance_call}, "latest"])
            balance = quantize_decimal(Decimal(_to_hex_quantity(balance_raw)), int(decimals))
        else:
            balance_raw = self._rpc("eth_getBalance", [target.address, "latest"])
            balance = quantize_decimal(Decimal(_to_hex_quantity(balance_raw)), 18)
        tx_count_raw = self._rpc("eth_getTransactionCount", [target.address, "latest"])
        return MonitoringSnapshot(
            name=target.name,
            token=target.token,
            network=target.network,
            chain=target.chain,
            provider=self.config.name,
            address=target.address,
            balance=balance,
            asset_type=target.asset_type,
            identifier=target.identifier,
            quote_currency=target.quote_currency,
            metadata={"transaction_count": str(_to_hex_quantity(tx_count_raw))},
        )


class SolanaRpcProviderAdapter(ProviderAdapter):
    def _rpc(self, method: str, params: List[Any]) -> Any:
        endpoint = self.config.endpoint()
        if not endpoint:
            raise ConfigError(f"provider {self.config.name} has no rpc endpoint")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        result = self.transport.request_json("POST", endpoint, json_body=payload)
        if "error" in result:
            raise ProviderError(f"{self.config.name} {method} failed: {result['error']}")
        return result.get("result")

    def fetch_wallet_asset(self, target: WalletAssetConfig) -> MonitoringSnapshot:
        if normalize_chain(target.chain) not in SOLANA_CHAINS:
            raise ProviderError(f"{self.config.name} does not support chain {target.chain}")
        if target.contract:
            result = self._rpc(
                "getTokenAccountsByOwner",
                [
                    target.address,
                    {"mint": target.contract},
                    {"encoding": "jsonParsed"},
                ],
            )
            total = Decimal(0)
            for item in result.get("value", []):
                amount_info = item.get("account", {}).get("data", {}).get("parsed", {}).get("info", {}).get("tokenAmount", {})
                raw = amount_info.get("uiAmountString")
                if raw is not None:
                    total += parse_decimal(raw, field_name="uiAmountString")
                else:
                    amount = parse_decimal(amount_info.get("amount", "0"), field_name="amount")
                    decimals = int(amount_info.get("decimals", 0))
                    total += quantize_decimal(amount, decimals)
            balance = total
        else:
            result = self._rpc("getBalance", [target.address])
            balance = quantize_decimal(Decimal(str(result.get("value", 0))), 9)
        signatures = self._rpc("getSignaturesForAddress", [target.address, {"limit": 1}]) or []
        last_activity_at = None
        last_hash = None
        if signatures:
            entry = signatures[0]
            last_hash = entry.get("signature")
            block_time = entry.get("blockTime")
            if block_time is not None:
                last_activity_at = datetime.fromtimestamp(int(block_time), tz=timezone.utc)
        inactivity_seconds = int((utcnow() - last_activity_at).total_seconds()) if last_activity_at else None
        return MonitoringSnapshot(
            name=target.name,
            token=target.token,
            network=target.network,
            chain=target.chain,
            provider=self.config.name,
            address=target.address,
            balance=balance,
            asset_type=target.asset_type,
            identifier=target.identifier,
            quote_currency=target.quote_currency,
            last_activity_at=last_activity_at,
            last_transaction_hash=last_hash,
            inactivity_seconds=inactivity_seconds,
        )


class BitgetPriceProviderAdapter(ProviderAdapter):
    def _make_request_checksum(self, path: str, body_str: str, timestamp_ms: str) -> str:
        digest = hashlib.sha256(f"POST{path}{body_str}{timestamp_ms}".encode("utf-8")).hexdigest()
        return "0x" + digest

    def fetch_wallet_asset(self, target: WalletAssetConfig) -> MonitoringSnapshot:
        raise ProviderError(f"{self.config.name} is a price-only provider")

    def fetch_price(self, target: WalletAssetConfig) -> Optional[Decimal]:
        if normalize_chain(target.chain) not in EVM_CHAINS:
            raise ProviderError(f"{self.config.name} currently supports EVM token pricing only")
        contract = (
            target.contract
            or str(target.metadata.get("pricing_contract") or "").strip()
            or str((self.config.options.get("native_contracts") or {}).get(target.chain) or "").strip()
        )
        if not contract:
            raise ProviderError(f"{self.config.name} requires an EVM token contract or pricing_contract metadata for pricing")
        path = "/market/v3/coin/batchGetBaseInfo"
        url = (self.config.base_url or BITGET_BASE_URL).rstrip("/") + path
        body = {"list": [{"chain": target.chain, "contract": contract}]}
        body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        timestamp_ms = str(int(time.time() * 1000))
        headers = {
            "Content-Type": "application/json",
            "channel": "toc_agent",
            "brand": "toc_agent",
            "clientversion": "10.0.0",
            "language": "en",
            "token": "toc_agent",
            # Bitget's public agent API expects this deterministic request checksum header.
            "X-SIGN": self._make_request_checksum(path, body_str, timestamp_ms),
            "X-TIMESTAMP": timestamp_ms,
        }
        result = self.transport.request_json("POST", url, json_body=body, headers=headers)
        items = result.get("data", {}).get("list", [])
        if not items:
            return None
        price = items[0].get("price")
        return parse_decimal(price, field_name="price") if price not in (None, "") else None


class ProviderRegistry:
    def __init__(self, providers: Iterable[ProviderConfig], *, transports: Optional[Mapping[str, HttpTransport]] = None):
        self.providers: Dict[str, ProviderAdapter] = {}
        transports = transports or {}
        for provider in providers:
            transport = transports.get(provider.name)
            if provider.type == "static":
                adapter = StaticProviderAdapter(provider, transport=transport)
            elif provider.type == "evm_rpc":
                adapter = EvmRpcProviderAdapter(provider, transport=transport)
            elif provider.type == "solana_rpc":
                adapter = SolanaRpcProviderAdapter(provider, transport=transport)
            elif provider.type == "bitget_price":
                adapter = BitgetPriceProviderAdapter(provider, transport=transport)
            else:
                raise ConfigError(f"unsupported provider type: {provider.type}")
            self.providers[provider.name] = adapter

    def get(self, name: str) -> ProviderAdapter:
        try:
            return self.providers[name]
        except KeyError as exc:
            raise ConfigError(f"unknown provider: {name}") from exc


def _target_lookup_key(target: WalletAssetConfig) -> str:
    return f"{target.asset_type}:{target.chain or 'general'}:{target.identifier}:{target.contract or 'native'}:{target.symbol}"


def _normalize_history_points(points: Any, *, quote_currency: str) -> List[Dict[str, Any]]:
    if not points:
        return []
    normalized: List[Dict[str, Any]] = []
    if not isinstance(points, list):
        raise ConfigError("recent_history must be a list")
    for item in points:
        if not isinstance(item, Mapping):
            raise ConfigError("recent_history entries must be objects")
        timestamp = format_iso_datetime(parse_iso_datetime(item.get("timestamp")))
        if timestamp is None:
            raise ConfigError("recent_history entries require timestamp")
        entry: Dict[str, Any] = {"timestamp": timestamp}
        if item.get("balance") is not None:
            entry["balance"] = decimal_to_str(parse_decimal(item.get("balance"), field_name="history.balance"))
        if item.get("approximate_value") is not None:
            entry["approximate_value"] = decimal_to_str(parse_decimal(item.get("approximate_value"), field_name="history.approximate_value"))
        entry["quote_currency"] = str(item.get("quote_currency") or quote_currency).upper()
        normalized.append(entry)
    return normalized


def _build_aggregates(snapshots: List[MonitoringSnapshot]) -> Dict[str, Any]:
    totals_by_currency: Dict[str, Decimal] = {}
    totals_by_type: Dict[str, Dict[str, Any]] = {}
    history_totals: Dict[tuple[str, str], Decimal] = {}
    for snapshot in snapshots:
        totals_by_type.setdefault(snapshot.asset_type, {"count": 0, "approximate_value": {}})
        totals_by_type[snapshot.asset_type]["count"] += 1
        if snapshot.approximate_value is not None:
            totals_by_currency[snapshot.quote_currency] = totals_by_currency.get(snapshot.quote_currency, Decimal(0)) + snapshot.approximate_value
            type_values = totals_by_type[snapshot.asset_type]["approximate_value"]
            type_values[snapshot.quote_currency] = type_values.get(snapshot.quote_currency, Decimal(0)) + snapshot.approximate_value
        for point in snapshot.recent_history:
            if point.get("approximate_value") is None:
                continue
            key = (point["timestamp"], point["quote_currency"])
            history_totals[key] = history_totals.get(key, Decimal(0)) + parse_decimal(point["approximate_value"], field_name="history.approximate_value")
    rendered_by_type = {
        asset_type: {
            "count": payload["count"],
            "approximate_value": {currency: decimal_to_str(value) for currency, value in payload["approximate_value"].items()},
        }
        for asset_type, payload in totals_by_type.items()
    }
    return {
        "asset_count": len(snapshots),
        "totals_by_quote_currency": {currency: decimal_to_str(value) for currency, value in totals_by_currency.items()},
        "totals_by_asset_type": rendered_by_type,
        "recent_history": [
            {"timestamp": timestamp, "quote_currency": currency, "approximate_value": decimal_to_str(value)}
            for (timestamp, currency), value in sorted(history_totals.items())
        ],
    }


def build_alerts(snapshot: MonitoringSnapshot, rules: AlertRuleConfig) -> List[MonitoringAlert]:
    alerts: List[MonitoringAlert] = []
    if rules.inactivity_seconds is not None and snapshot.inactivity_seconds is not None and snapshot.inactivity_seconds >= rules.inactivity_seconds:
        alerts.append(
            MonitoringAlert(
                severity="warning",
                rule="inactivity",
                wallet=snapshot.name,
                message=f"{snapshot.name} has been inactive for {snapshot.inactivity_seconds} seconds",
                observed_value=str(snapshot.inactivity_seconds),
            )
        )
    if rules.min_balance is not None and snapshot.balance < rules.min_balance:
        alerts.append(
            MonitoringAlert(
                severity="warning",
                rule="min_balance",
                wallet=snapshot.name,
                message=f"{snapshot.name} balance fell below the configured threshold",
                observed_value=decimal_to_str(snapshot.balance),
            )
        )
    if rules.max_balance is not None and snapshot.balance > rules.max_balance:
        alerts.append(
            MonitoringAlert(
                severity="info",
                rule="max_balance",
                wallet=snapshot.name,
                message=f"{snapshot.name} balance exceeded the configured threshold",
                observed_value=decimal_to_str(snapshot.balance),
            )
        )
    if rules.large_value_threshold is not None and snapshot.approximate_value is not None and snapshot.approximate_value >= rules.large_value_threshold:
        alerts.append(
            MonitoringAlert(
                severity="info",
                rule="large_value",
                wallet=snapshot.name,
                message=f"{snapshot.name} approximate value exceeded the configured threshold",
                observed_value=decimal_to_str(snapshot.approximate_value),
            )
        )
    if rules.large_transaction_value is not None and snapshot.last_transaction_value is not None and snapshot.last_transaction_value >= rules.large_transaction_value:
        alerts.append(
            MonitoringAlert(
                severity="warning",
                rule="large_transaction",
                wallet=snapshot.name,
                message=f"{snapshot.name} last transaction exceeded the configured threshold",
                observed_value=decimal_to_str(snapshot.last_transaction_value),
            )
        )
    return alerts


class MonitoringService:
    def __init__(self, config: MonitorConfig, *, registry: Optional[ProviderRegistry] = None, logger: Optional[logging.Logger] = None):
        self.config = config
        self.registry = registry or ProviderRegistry(config.providers)
        self.logger = logger or logging.getLogger("bgw.monitoring")
        self.last_result: Optional[Dict[str, Any]] = None
        self._lock = RLock()

    def refresh(self) -> Dict[str, Any]:
        with self._lock:
            snapshots: List[MonitoringSnapshot] = []
            alerts: List[MonitoringAlert] = []
            errors: List[Dict[str, str]] = []
            for target in self.config.wallets:
                rules = self.config.default_alerts.merged_with(target.alerts)
                try:
                    snapshot = self.registry.get(target.provider).fetch_wallet_asset(target)
                    if snapshot.last_activity_at and snapshot.inactivity_seconds is None:
                        snapshot.inactivity_seconds = int((snapshot.last_updated_at - snapshot.last_activity_at).total_seconds())
                    if target.price_provider:
                        try:
                            price = self.registry.get(target.price_provider).fetch_price(target)
                        except (ProviderError, ConfigError) as exc:
                            error = {"wallet": target.name, "provider": target.price_provider, "error": str(exc)}
                            errors.append(error)
                            emit_log(self.logger, logging.WARNING, "monitoring.provider_error", wallet=target.name, provider=target.price_provider, error=str(exc))
                            continue
                        if price is not None:
                            snapshot.approximate_value = snapshot.balance * price
                    snapshots.append(snapshot)
                    alerts.extend(build_alerts(snapshot, rules))
                except (ProviderError, ConfigError) as exc:
                    error = {"wallet": target.name, "provider": target.provider, "error": str(exc)}
                    errors.append(error)
                    emit_log(self.logger, logging.WARNING, "monitoring.provider_error", wallet=target.name, provider=target.provider, error=str(exc))
            status = "ok" if not errors else ("degraded" if snapshots else "error")
            self.last_result = {
                "status": status,
                "updated_at": format_iso_datetime(utcnow()),
                "snapshots": [item.to_dict() for item in snapshots],
                "aggregates": _build_aggregates(snapshots),
                "alerts": [item.to_dict() for item in alerts],
                "errors": errors,
            }
            return self.last_result

    def health(self) -> Dict[str, Any]:
        with self._lock:
            result = self.last_result
        if result is None:
            result = self.refresh()
        return {
            "status": result["status"],
            "updated_at": result["updated_at"],
            "providers": [provider.healthcheck() for provider in self.registry.providers.values()],
            "errors": result["errors"],
        }


class MonitoringRequestHandler(BaseHTTPRequestHandler):
    server_version = "BGWMonitoring/1.0"

    def _send_json(self, code: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        service = getattr(self.server, "monitoring_service", None)
        if service is None:
            self._send_json(500, {"status": "error", "error": "monitoring service not attached"})
            return
        query = parse_qs(parsed.query)
        refresh = query.get("refresh", ["0"])[0] == "1"
        if parsed.path == "/healthz":
            if refresh:
                service.refresh()
            self._send_json(200, service.health())
            emit_log(service.logger, logging.INFO, "monitoring.http", method="GET", path=parsed.path, status_code=200, refresh=refresh)
            return
        if parsed.path == "/status":
            payload = service.refresh() if refresh or service.last_result is None else service.last_result
            self._send_json(200, payload)
            emit_log(service.logger, logging.INFO, "monitoring.http", method="GET", path=parsed.path, status_code=200, refresh=refresh)
            return
        if parsed.path == "/totals":
            payload = service.refresh() if refresh or service.last_result is None else service.last_result
            self._send_json(200, {"status": payload["status"], "updated_at": payload["updated_at"], "aggregates": payload["aggregates"]})
            emit_log(service.logger, logging.INFO, "monitoring.http", method="GET", path=parsed.path, status_code=200, refresh=refresh)
            return
        if parsed.path == "/alerts":
            payload = service.refresh() if refresh or service.last_result is None else service.last_result
            self._send_json(200, {"status": payload["status"], "updated_at": payload["updated_at"], "alerts": payload["alerts"], "errors": payload["errors"]})
            emit_log(service.logger, logging.INFO, "monitoring.http", method="GET", path=parsed.path, status_code=200, refresh=refresh)
            return
        self._send_json(404, {"status": "not_found", "path": parsed.path})
        emit_log(service.logger, logging.INFO, "monitoring.http", method="GET", path=parsed.path, status_code=404, refresh=refresh)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def _default_config_path() -> str:
    return os.environ.get("BGW_MONITOR_CONFIG", "")


def load_service(config_path: str) -> MonitoringService:
    logger = logging.getLogger("bgw.monitoring")
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO)
    config = MonitorConfig.load(config_path)
    return MonitoringService(config, logger=logger)


def _cmd_status(args: argparse.Namespace) -> None:
    service = load_service(args.config)
    print(json.dumps(service.refresh(), ensure_ascii=False, indent=2))


def _cmd_health(args: argparse.Namespace) -> None:
    service = load_service(args.config)
    service.refresh()
    print(json.dumps(service.health(), ensure_ascii=False, indent=2))


def _cmd_serve(args: argparse.Namespace) -> None:
    service = load_service(args.config)
    service.refresh()
    server = ThreadingHTTPServer((args.host, args.port), MonitoringRequestHandler)
    server.monitoring_service = service  # type: ignore[attr-defined]
    emit_log(service.logger, logging.INFO, "monitoring.server_started", host=args.host, port=args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        emit_log(service.logger, logging.INFO, "monitoring.server_stopped")
    finally:
        server.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only wallet monitoring with extensible providers")
    parser.add_argument("--config", default=_default_config_path(), help="Path to monitoring JSON config")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="Refresh monitoring data and print JSON status")
    p.set_defaults(func=_cmd_status)

    p = sub.add_parser("health", help="Refresh monitoring data and print health JSON")
    p.set_defaults(func=_cmd_health)

    p = sub.add_parser("serve", help="Serve internal read-only monitoring API")
    p.add_argument("--host", default=os.environ.get("BGW_MONITOR_BIND_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("BGW_MONITOR_BIND_PORT", "8787")))
    p.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    if not args.config:
        parser.error("monitoring config is required via --config or BGW_MONITOR_CONFIG")
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
