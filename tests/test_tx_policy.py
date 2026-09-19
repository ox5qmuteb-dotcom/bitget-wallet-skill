import unittest

from scripts.tx_policy import (
    PolicyConfig,
    PolicyError,
    TransferRequest,
    create_preview_approval_token,
    evaluate_transfer,
    sanitize_audit_log,
)


class TxPolicyTest(unittest.TestCase):
    def setUp(self):
        self.cfg = PolicyConfig(
            allowlist={
                "eth": {"0x1111111111111111111111111111111111111111"},
                "sol": {"FhtA8m3q2V5M45gYtW9baK7Jj8UPdLQ4XcNf1fKrL3Qw"},
                "base": {"0x2222222222222222222222222222222222222222"},
            },
            allow_native_transfer=False,
            allow_override_7702=False,
            allow_approve=False,
            allow_permit=False,
            per_tx_limit=100.0,
            daily_limit=500.0,
            session_limit=200.0,
        )

    def test_rejects_non_allowlisted_recipient_before_sign(self):
        req = TransferRequest(
            chain="eth",
            recipient="0x3333333333333333333333333333333333333333",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        with self.assertRaisesRegex(PolicyError, "recipient is not allowlisted"):
            evaluate_transfer(req, self.cfg)

    def test_rejects_native_transfer_by_default(self):
        req = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="",
        )
        with self.assertRaisesRegex(PolicyError, "native-token transfers"):
            evaluate_transfer(req, self.cfg)

    def test_rejects_approve_and_permit_by_default(self):
        approve_req = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            calldata="0x095ea7b3deadbeef",
        )
        permit_req = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            action="permit",
            calldata="0xd505accfdeadbeef",
        )
        with self.assertRaisesRegex(PolicyError, "approve is disabled"):
            evaluate_transfer(approve_req, self.cfg)
        with self.assertRaisesRegex(PolicyError, "permit is disabled"):
            evaluate_transfer(permit_req, self.cfg)

    def test_rejects_per_tx_daily_and_session_limits(self):
        per_tx = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=150.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        with self.assertRaisesRegex(PolicyError, "per-transaction"):
            evaluate_transfer(per_tx, self.cfg)

        daily = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=50.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        with self.assertRaisesRegex(PolicyError, "daily limit"):
            evaluate_transfer(daily, self.cfg, daily_spent=460.0)

        session = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=50.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        with self.assertRaisesRegex(PolicyError, "session limit"):
            evaluate_transfer(session, self.cfg, session_spent=170.0)

    def test_rejects_override_7702_by_default(self):
        req = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            override_7702=True,
        )
        with self.assertRaisesRegex(PolicyError, "override-7702"):
            evaluate_transfer(req, self.cfg)

    def test_submit_requires_preview_bound_approval_token(self):
        preview = {
            "chain": "eth",
            "to": "0x1111111111111111111111111111111111111111",
            "contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "amount": "1.0",
        }
        bad_submit = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            is_submit=True,
            preview_payload=preview,
            approval_token="pvw_invalid",
        )
        with self.assertRaisesRegex(PolicyError, "does not match preview payload"):
            evaluate_transfer(bad_submit, self.cfg)

        ok_submit = TransferRequest(
            chain="eth",
            recipient="0x1111111111111111111111111111111111111111",
            amount=1.0,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            is_submit=True,
            preview_payload=preview,
            approval_token=create_preview_approval_token(preview),
        )
        self.assertTrue(evaluate_transfer(ok_submit, self.cfg))

    def test_solana_allowlisted_path_supported(self):
        req = TransferRequest(
            chain="sol",
            recipient="FhtA8m3q2V5M45gYtW9baK7Jj8UPdLQ4XcNf1fKrL3Qw",
            amount=1.0,
            contract="So11111111111111111111111111111111111111112",
        )
        self.assertTrue(evaluate_transfer(req, self.cfg))

    def test_social_login_flow_still_requires_submit_binding(self):
        preview = {
            "chain": "base",
            "to": "0x2222222222222222222222222222222222222222",
            "walletType": "social",
            "amount": "2.0",
            "contract": "0x4200000000000000000000000000000000000006",
        }
        req = TransferRequest(
            chain="base",
            recipient="0x2222222222222222222222222222222222222222",
            amount=2.0,
            contract="0x4200000000000000000000000000000000000006",
            is_submit=True,
            preview_payload=preview,
            approval_token="",
        )
        with self.assertRaisesRegex(PolicyError, "approval token"):
            evaluate_transfer(req, self.cfg)

    def test_audit_log_redacts_sensitive_fields(self):
        audit = {
            "chain": "eth",
            "mnemonic": "word word word",
            "private_key": "0xabc",
            "signature": "0xdeadbeef",
            "nested": {"sig": "0xbeef", "safe": "ok"},
        }
        sanitized = sanitize_audit_log(audit)
        self.assertEqual(sanitized["mnemonic"], "[REDACTED]")
        self.assertEqual(sanitized["private_key"], "[REDACTED]")
        self.assertEqual(sanitized["signature"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["sig"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["safe"], "ok")


if __name__ == "__main__":
    unittest.main()
