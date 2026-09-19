import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def load_script_module(filename: str, module_name: str):
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_policy(data: dict) -> str:
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
    json.dump(data, handle)
    handle.flush()
    handle.close()
    return handle.name


class PolicyEntrypointTest(unittest.TestCase):
    def test_transfer_preview_only_does_not_import_api(self):
        module = load_script_module("transfer_make_sign_send.py", "transfer_make_sign_send_test_preview")
        policy_path = write_policy(
            {
                "enabled": True,
                "mode": "preview-first",
                "allowlist": {"eth": ["0x1111111111111111111111111111111111111111"]},
                "supported_assets": {"eth": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"]},
            }
        )
        argv = [
            "transfer_make_sign_send.py",
            "--policy-file",
            policy_path,
            "--preview-only",
            "--chain",
            "eth",
            "--contract",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "--from-address",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--to-address",
            "0x1111111111111111111111111111111111111111",
            "--amount",
            "1",
        ]
        stdout = io.StringIO()
        with mock.patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
            module.main()
        preview = json.loads(stdout.getvalue())
        self.assertEqual(preview["mode"], "preview-only")
        self.assertTrue(preview["approvalToken"].startswith("pvw_"))

    def test_transfer_execution_without_approval_denies_before_network(self):
        module = load_script_module("transfer_make_sign_send.py", "transfer_make_sign_send_test_deny")
        policy_path = write_policy(
            {
                "enabled": True,
                "mode": "preview-first",
                "allowlist": {"eth": ["0x1111111111111111111111111111111111111111"]},
                "supported_assets": {"eth": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"]},
            }
        )
        argv = [
            "transfer_make_sign_send.py",
            "--policy-file",
            policy_path,
            "--chain",
            "eth",
            "--contract",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "--from-address",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--to-address",
            "0x1111111111111111111111111111111111111111",
            "--amount",
            "1",
        ]
        stderr = io.StringIO()
        with mock.patch("sys.argv", argv), \
             mock.patch.object(module.importlib, "import_module", side_effect=AssertionError("API should not be imported")), \
             contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit):
            module.main()
        self.assertIn("approval token", stderr.getvalue())

    def test_order_preview_only_does_not_import_api(self):
        module = load_script_module("order_make_sign_send.py", "order_make_sign_send_test_preview")
        policy_path = write_policy(
            {
                "enabled": True,
                "mode": "preview-first",
                "allow_swap": True,
                "allowlist": {"eth": ["0x1111111111111111111111111111111111111111"]},
                "supported_assets": {"eth": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"]},
            }
        )
        argv = [
            "order_make_sign_send.py",
            "--policy-file",
            policy_path,
            "--preview-only",
            "--order-id",
            "order_123",
            "--from-address",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--to-address",
            "0x1111111111111111111111111111111111111111",
            "--from-chain",
            "eth",
            "--from-contract",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "--from-symbol",
            "USDC",
            "--to-chain",
            "eth",
            "--to-contract",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "--to-symbol",
            "USDC",
            "--from-amount",
            "1",
            "--slippage",
            "0.5",
            "--market",
            "demo-market",
            "--protocol",
            "demo-protocol",
        ]
        stdout = io.StringIO()
        with mock.patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
            module.main()
        preview = json.loads(stdout.getvalue())
        self.assertEqual(preview["preview"]["kind"], "swap")
        self.assertEqual(preview["preview"]["orderId"], "order_123")

    def test_order_sign_cli_denies_without_explicit_override(self):
        module = load_script_module("order_sign.py", "order_sign_test_cli")
        stderr = io.StringIO()
        with mock.patch("sys.argv", ["order_sign.py"]), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            module.main()
        self.assertIn("standalone order_sign.py CLI execution is disabled by default", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
