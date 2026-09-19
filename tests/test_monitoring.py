from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from scripts.monitoring import (
    AlertRuleConfig,
    ConfigError,
    EvmRpcProviderAdapter,
    HttpTransport,
    MonitorConfig,
    MonitoringService,
    MonitoringRequestHandler,
    ProviderConfig,
    ProviderError,
    SolanaRpcProviderAdapter,
    ThreadingHTTPServer,
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


class FakeJsonErrorResponse:
    status_code = 200
    text = "not-json"

    def json(self):
        raise ValueError("bad json")


class MonitoringTests(unittest.TestCase):
    def test_parse_decimal_rejects_bad_format_and_handles_large_values(self):
        value = parse_decimal("123456789012345678901234567890.000001", field_name="balance")
        self.assertEqual(value, Decimal("123456789012345678901234567890.000001"))
        self.assertEqual(parse_decimal(1.5, field_name="balance"), Decimal("1.5"))
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

    def test_invalid_contract_is_rejected_in_config(self):
        with self.assertRaises(ConfigError):
            MonitorConfig.from_mapping(
                {
                    "providers": [{"name": "static-balance", "type": "static", "options": {}}],
                    "wallets": [
                        {
                            "name": "Broken Token",
                            "network": "Base",
                            "chain": "base",
                            "token": "USDC",
                            "contract": "not-a-contract",
                            "address": "0x1111111111111111111111111111111111111111",
                            "provider": "static-balance",
                        }
                    ],
                }
            )

    def test_negative_alert_and_provider_settings_are_rejected(self):
        with self.assertRaises(ConfigError):
            MonitorConfig.from_mapping(
                {
                    "providers": [{"name": "static-balance", "type": "static", "options": {}}],
                    "wallets": [
                        {
                            "name": "ETH Wallet",
                            "network": "Ethereum",
                            "chain": "eth",
                            "token": "ETH",
                            "address": "0x1111111111111111111111111111111111111111",
                            "provider": "static-balance",
                            "alerts": {"inactivity_seconds": -1},
                        }
                    ],
                }
            )
        for field in ("min_balance", "max_balance", "large_transaction_value", "large_value_threshold"):
            with self.subTest(field=field):
                with self.assertRaises(ConfigError):
                    MonitorConfig.from_mapping(
                        {
                            "providers": [{"name": "static-balance", "type": "static", "options": {}}],
                            "wallets": [
                                {
                                    "name": "ETH Wallet",
                                    "network": "Ethereum",
                                    "chain": "eth",
                                    "token": "ETH",
                                    "address": "0x1111111111111111111111111111111111111111",
                                    "provider": "static-balance",
                                    "alerts": {field: "-1"},
                                }
                            ],
                        }
                    )
        with self.assertRaises(ConfigError):
            ProviderConfig.from_mapping({"name": "bad", "type": "evm_rpc", "rpc_url": "https://rpc.example", "timeout_seconds": 0})
        with self.assertRaises(ConfigError):
            ProviderConfig.from_mapping({"name": "bad", "type": "evm_rpc", "rpc_url": "https://rpc.example", "timeout_seconds": "abc"})
        with self.assertRaises(ConfigError):
            ProviderConfig.from_mapping({"name": "bad", "type": "evm_rpc", "rpc_url": "https://rpc.example", "timeout_seconds": float("inf")})
        with self.assertRaises(ConfigError):
            ProviderConfig.from_mapping({"name": "bad", "type": "evm_rpc", "rpc_url": "https://rpc.example", "retries": -1})
        with self.assertRaises(ConfigError):
            MonitorConfig.from_mapping(
                {
                    "providers": [{"name": "static-balance", "type": "static", "options": {}}],
                    "wallets": [
                        {
                            "name": "ETH Wallet",
                            "network": "Ethereum",
                            "chain": "eth",
                            "token": "ETH",
                            "address": "0x1111111111111111111111111111111111111111",
                            "provider": "static-balance",
                            "alerts": {"inactivity_seconds": 1.9},
                        }
                    ],
                }
            )

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

    def test_large_negative_transaction_does_not_trigger_positive_threshold_alert(self):
        from scripts.monitoring import MonitoringSnapshot

        snapshot = MonitoringSnapshot(
            name="Treasury ETH",
            network="Ethereum",
            chain="eth",
            token="USDC",
            address="0x1111111111111111111111111111111111111111",
            provider="static",
            balance=Decimal("100"),
            last_transaction_value=Decimal("-1200"),
        )
        alerts = build_alerts(snapshot, AlertRuleConfig(large_transaction_value=Decimal("1000")))
        self.assertEqual(alerts, [])

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

    def test_service_reports_degraded_when_some_wallets_succeed(self):
        config = MonitorConfig.from_mapping(
            {
                "providers": [
                    {
                        "name": "static-balance",
                        "type": "static",
                        "options": {
                            "snapshots": {
                                "ETH Wallet": {
                                    "balance": "1",
                                    "last_transaction_hash": "0x1"
                                }
                            }
                        },
                    }
                ],
                "wallets": [
                    {
                        "name": "ETH Wallet",
                        "network": "Ethereum",
                        "chain": "eth",
                        "token": "ETH",
                        "address": "0x1111111111111111111111111111111111111111",
                        "provider": "static-balance",
                    },
                    {
                        "name": "Broken Wallet",
                        "network": "Ethereum",
                        "chain": "eth",
                        "token": "ETH",
                        "address": "0x2222222222222222222222222222222222222222",
                        "provider": "static-balance",
                    },
                ],
            }
        )
        result = MonitoringService(config).refresh()
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(len(result["snapshots"]), 1)
        self.assertEqual(result["snapshots"][0]["name"], "ETH Wallet")
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

    def test_evm_rpc_uses_configured_decimals_without_extra_rpc_call(self):
        transport = FakeTransport(
            [
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
                metadata={"decimals": 6},
            )
        )
        self.assertEqual(snapshot.balance, Decimal("1"))
        self.assertEqual(len(transport.calls), 2)

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

    def test_solana_rpc_parses_token_accounts(self):
        transport = FakeTransport(
            [
                {
                    "result": {
                        "value": [
                            {
                                "account": {
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "tokenAmount": {
                                                    "uiAmountString": "1.25"
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            {
                                "account": {
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "tokenAmount": {
                                                    "amount": "250",
                                                    "decimals": 2
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        ]
                    }
                },
                {"result": []},
            ]
        )
        adapter = SolanaRpcProviderAdapter(
            ProviderConfig(name="sol", type="solana_rpc", rpc_url="https://sol.example"),
            transport=transport,
        )
        snapshot = adapter.fetch_wallet_asset(
            WalletAssetConfig(
                name="USDC",
                network="Solana",
                chain="sol",
                token="USDC",
                address="11111111111111111111111111111111",
                provider="sol",
                contract="So11111111111111111111111111111111111111112",
            )
        )
        self.assertEqual(snapshot.balance, Decimal("3.75"))

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

    def test_http_transport_wraps_invalid_json(self):
        class FakeSession:
            def request(self, **kwargs):
                return FakeJsonErrorResponse()

        transport = HttpTransport(session=FakeSession())
        with self.assertRaises(ProviderError):
            transport.request_json("POST", "https://rpc.example", json_body={"jsonrpc": "2.0"})

    def test_http_endpoints_return_status_and_health(self):
        config = MonitorConfig.from_mapping(
            {
                "providers": [
                    {
                        "name": "static-balance",
                        "type": "static",
                        "options": {
                            "snapshots": {
                                "ETH Wallet": {
                                    "balance": "1.5",
                                    "last_transaction_hash": "0x1"
                                }
                            }
                        },
                    }
                ],
                "wallets": [
                    {
                        "name": "ETH Wallet",
                        "network": "Ethereum",
                        "chain": "eth",
                        "token": "ETH",
                        "address": "0x1111111111111111111111111111111111111111",
                        "provider": "static-balance",
                    }
                ],
            }
        )
        service = MonitoringService(config)
        server = ThreadingHTTPServer(("127.0.0.1", 0), MonitoringRequestHandler)
        server.monitoring_service = service  # type: ignore[attr-defined]
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with urlopen(base + "/status?refresh=1") as response:
                status_payload = json.load(response)
            with urlopen(base + "/healthz?refresh=1") as response:
                health_payload = json.load(response)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(status_payload["status"], "ok")
        self.assertEqual(status_payload["snapshots"][0]["name"], "ETH Wallet")
        self.assertEqual(health_payload["status"], "ok")
        self.assertEqual(health_payload["providers"][0]["provider"], "static-balance")

    def test_http_endpoint_returns_json_when_service_missing(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), MonitoringRequestHandler)
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            try:
                with urlopen(f"http://127.0.0.1:{server.server_port}/status") as response:
                    payload = json.load(response)
                    status_code = response.status
            except HTTPError as exc:
                payload = json.load(exc)
                status_code = exc.code
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(status_code, 500)
        self.assertEqual(payload["status"], "error")


if __name__ == "__main__":
    unittest.main()
