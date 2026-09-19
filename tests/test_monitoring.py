from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

from scripts.monitoring import (
    AlertRuleConfig,
    ConfigError,
    EvmRpcProviderAdapter,
    HttpTransport,
    MonitorConfig,
    MonitoringService,
    ProviderConfig,
    ProviderError,
    ProviderRegistry,
    SolanaRpcProviderAdapter,
    StaticProviderAdapter,
    WalletAssetConfig,
    build_alerts,
    ensure_no_plaintext_secrets,
    parse_decimal,
    redact_sensitive_data,
    validate_public_address,
)


class FakeTransport(HttpTransport):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request_json(self, method, url, *, json_body=None, headers=None):
        self.calls.append({"method": method, "url": url, "json_body": json_body, "headers": headers or {}})
        if not self.responses:
            raise ProviderError("no fake response left")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class MonitoringTests(unittest.TestCase):
    def test_parse_decimal_rejects_bad_format_and_handles_large_values(self):
        value = parse_decimal("123456789012345678901234567890.000001", field_name="balance")
        self.assertEqual(value, Decimal("123456789012345678901234567890.000001"))
        with self.assertRaises(ConfigError):
            parse_decimal("NaN", field_name="balance")
        with self.assertRaises(ConfigError):
            parse_decimal("1.2.3", field_name="balance")

    def test_validate_public_address_for_evm_and_solana(self):
        self.assertTrue(validate_public_address("eth", "0x1111111111111111111111111111111111111111"))
        self.assertFalse(validate_public_address("eth", "0x123"))
        self.assertTrue(validate_public_address("sol", "11111111111111111111111111111111"))
        self.assertFalse(validate_public_address("sol", "not-base58-0000"))

    def test_redact_sensitive_data(self):
        sanitized = redact_sensitive_data(
            {
                "private_key": "0xabc",
                "signature": "0xdead",
                "nested": {"password": "secret", "address": "0x1111111111111111111111111111111111111111"},
            }
        )
        self.assertEqual(sanitized["private_key"], "[REDACTED]")
        self.assertEqual(sanitized["signature"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["password"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["address"], "0x1111111111111111111111111111111111111111")

    def test_secret_fields_are_rejected_in_config(self):
        with self.assertRaises(ConfigError):
            ensure_no_plaintext_secrets({"providers": [], "private_key": "0xabc"})

    def test_build_alerts_for_inactivity_balance_and_large_values(self):
        now = datetime.now(timezone.utc)
        from scripts.monitoring import MonitoringSnapshot

        snapshot = MonitoringSnapshot(
            name="Treasury ETH",
            network="Ethereum",
            chain="eth",
            token="USDC",
            address="0x1111111111111111111111111111111111111111",
            provider="static",
            balance=Decimal("9.5"),
            approximate_value=Decimal("15000"),
            last_activity_at=now - timedelta(hours=30),
            last_transaction_hash="0xabc",
            last_transaction_value=Decimal("1200"),
            inactivity_seconds=30 * 60 * 60,
        )
        alerts = build_alerts(
            snapshot,
            AlertRuleConfig(
                inactivity_seconds=24 * 60 * 60,
                min_balance=Decimal("10"),
                large_transaction_value=Decimal("1000"),
                large_value_threshold=Decimal("10000"),
            ),
        )
        self.assertEqual({item.rule for item in alerts}, {"inactivity", "min_balance", "large_transaction", "large_value"})

    def test_static_provider_and_service_refresh(self):
        config = MonitorConfig.from_mapping(
            {
                "providers": [
                    {
                        "name": "static-balance",
                        "type": "static",
                        "options": {
                            "snapshots": {
                                "eth:0x1111111111111111111111111111111111111111:native:ETH": {
                                    "balance": "1000000.000000000000000001",
                                    "last_activity_at": "2026-01-01T00:00:00Z",
                                    "last_transaction_hash": "0xdeadbeef",
                                    "last_transaction_value": "250000",
                                }
                            },
                            "prices": {
                                "eth:0x1111111111111111111111111111111111111111:native:ETH": "2"
                            },
                        },
                    }
                ],
                "wallets": [
                    {
                        "name": "Treasury ETH",
                        "network": "Ethereum",
                        "chain": "eth",
                        "token": "ETH",
                        "address": "0x1111111111111111111111111111111111111111",
                        "provider": "static-balance",
                        "price_provider": "static-balance",
                        "alerts": {"large_transaction_value": "200000", "large_value_threshold": "100"},
                    }
                ],
            }
        )
        service = MonitoringService(config)
        result = service.refresh()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["snapshots"][0]["approximate_value"], "2000000.000000000000000002")
        self.assertEqual({item["rule"] for item in result["alerts"]}, {"large_transaction", "large_value"})

    def test_service_captures_provider_failure(self):
        config = MonitorConfig.from_mapping(
            {
                "providers": [{"name": "static-balance", "type": "static", "options": {}}],
                "wallets": [
                    {
                        "name": "Treasury ETH",
                        "network": "Ethereum",
                        "chain": "eth",
                        "token": "ETH",
                        "address": "0x1111111111111111111111111111111111111111",
                        "provider": "static-balance",
                    }
                ],
            }
        )
        result = MonitoringService(config).refresh()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["snapshots"], [])
        self.assertEqual(len(result["errors"]), 1)

    def test_evm_rpc_parses_erc20_balance_with_decimal_precision(self):
        transport = FakeTransport(
            [
                {"result": "0x06"},
                {"result": "0x0f4240"},
                {"result": "0x2a"},
            ]
        )
        adapter = EvmRpcProviderAdapter(
            ProviderConfig(name="evm", type="evm_rpc", rpc_url="https://rpc.example"),
            transport=transport,
        )
        snapshot = adapter.fetch_wallet_asset(
            WalletAssetConfig(
                name="USDC",
                network="Base",
                chain="base",
                token="USDC",
                address="0x1111111111111111111111111111111111111111",
                provider="evm",
                contract="0x2222222222222222222222222222222222222222",
            )
        )
        self.assertEqual(snapshot.balance, Decimal("1"))
        self.assertEqual(snapshot.metadata["transaction_count"], "42")

    def test_solana_rpc_uses_last_signature_for_inactivity(self):
        transport = FakeTransport(
            [
                {"result": {"value": 2500000000}},
                {"result": [{"signature": "sig-1", "blockTime": 1767225600}]},
            ]
        )
        adapter = SolanaRpcProviderAdapter(
            ProviderConfig(name="sol", type="solana_rpc", rpc_url="https://sol.example"),
            transport=transport,
        )
        snapshot = adapter.fetch_wallet_asset(
            WalletAssetConfig(
                name="SOL",
                network="Solana",
                chain="sol",
                token="SOL",
                address="11111111111111111111111111111111",
                provider="sol",
            )
        )
        self.assertEqual(snapshot.balance, Decimal("2.5"))
        self.assertEqual(snapshot.last_transaction_hash, "sig-1")
        self.assertIsNotNone(snapshot.inactivity_seconds)

    def test_rpc_failure_is_reported(self):
        transport = FakeTransport([ProviderError("timeout calling rpc")])
        adapter = SolanaRpcProviderAdapter(
            ProviderConfig(name="sol", type="solana_rpc", rpc_url="https://sol.example"),
            transport=transport,
        )
        with self.assertRaises(ProviderError):
            adapter.fetch_wallet_asset(
                WalletAssetConfig(
                    name="SOL",
                    network="Solana",
                    chain="sol",
                    token="SOL",
                    address="11111111111111111111111111111111",
                    provider="sol",
                )
            )


if __name__ == "__main__":
    unittest.main()
