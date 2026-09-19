import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path('/home/runner/work/bitget-wallet-skill/bitget-wallet-skill')
SCRIPTS_DIR = REPO_ROOT / 'scripts'
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import tx_policy


def load_script_module(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tempdir.name)
        self.policy_file = self.base / 'policy.json'
        self.state_file = self.base / 'state.json'
        self.audit_log = self.base / 'audit.ndjson'
        self.env = {
            'BGW_POLICY_STATE_FILE': str(self.state_file),
            'BGW_AUDIT_LOG': str(self.audit_log),
        }
        self.policy = {
            'enabled': True,
            'approval_ttl_seconds': 900,
            'allow_native_transfers': False,
            'allow_approvals': False,
            'allow_message_signing': False,
            'allow_eip7702_auth': False,
            'allow_override_7702': False,
            'allowed_chains': ['base', 'sol'],
            'allowed_from_addresses': [
                '0x1111111111111111111111111111111111111111',
                '11111111111111111111111111111111',
            ],
            'allowed_to_addresses': [
                '0x2222222222222222222222222222222222222222',
                'So11111111111111111111111111111111111111112',
            ],
            'allowed_contracts': [
                '0x3333333333333333333333333333333333333333',
                '0x4444444444444444444444444444444444444444',
                'So11111111111111111111111111111111111111112',
            ],
            'allowed_approval_contracts': [],
            'limits': {
                'default': {'per_tx': '25', 'daily': '30', 'session': '30'},
                'per_asset': {
                    'base:0x3333333333333333333333333333333333333333': {
                        'per_tx': '25', 'daily': '30', 'session': '30'
                    },
                    'sol:So11111111111111111111111111111111111111112': {
                        'per_tx': '5', 'daily': '10', 'session': '10'
                    },
                },
            },
        }
        self.policy_file.write_text(json.dumps(self.policy), encoding='utf-8')

    def tearDown(self):
        self.tempdir.cleanup()

    def _ctx(self):
        with mock.patch.dict(os.environ, self.env, clear=False):
            return tx_policy.load_policy_context(str(self.policy_file))

    def test_transfer_non_allowlisted_recipient_rejected_before_sign(self):
        intent = {
            'operation': 'transfer',
            'walletMode': 'local',
            'chain': 'base',
            'contract': '0x3333333333333333333333333333333333333333',
            'from': '0x1111111111111111111111111111111111111111',
            'to': '0x9999999999999999999999999999999999999999',
            'amount': '1',
            'memo': '',
            'gasless': False,
            'gaslessPayToken': '',
            'override7702': False,
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            with self.assertRaisesRegex(tx_policy.PolicyError, 'to address'):
                tx_policy.issue_preview(self._ctx(), intent)

    def test_native_transfer_rejected_by_default(self):
        intent = {
            'operation': 'transfer',
            'walletMode': 'local',
            'chain': 'base',
            'contract': '',
            'from': '0x1111111111111111111111111111111111111111',
            'to': '0x2222222222222222222222222222222222222222',
            'amount': '1',
            'memo': '',
            'gasless': False,
            'gaslessPayToken': '',
            'override7702': False,
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            with self.assertRaisesRegex(tx_policy.PolicyError, 'Native-token transfers'):
                tx_policy.issue_preview(self._ctx(), intent)

    def test_daily_limit_enforced_after_successful_submission(self):
        intent = {
            'operation': 'transfer',
            'walletMode': 'local',
            'chain': 'base',
            'contract': '0x3333333333333333333333333333333333333333',
            'from': '0x1111111111111111111111111111111111111111',
            'to': '0x2222222222222222222222222222222222222222',
            'amount': '20',
            'memo': '',
            'gasless': False,
            'gaslessPayToken': '',
            'override7702': False,
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            ctx = self._ctx()
            preview = tx_policy.issue_preview(ctx, intent)
            approved = tx_policy.require_approval(ctx, intent, preview['approvalToken'])
            tx_policy.record_success(ctx, approved, preview['approvalToken'], order_id='ord-1')
            with self.assertRaisesRegex(tx_policy.PolicyError, 'daily limit'):
                tx_policy.issue_preview(ctx, {**intent, 'amount': '15'})

    def test_swap_approval_calldata_blocked(self):
        intent = {
            'operation': 'swap',
            'walletMode': 'local',
            'orderId': 'ord-1',
            'fromChain': 'base',
            'fromContract': '0x3333333333333333333333333333333333333333',
            'fromSymbol': 'USDC',
            'fromAddress': '0x1111111111111111111111111111111111111111',
            'toChain': 'base',
            'toContract': '0x4444444444444444444444444444444444444444',
            'toSymbol': 'OTHER',
            'toAddress': '0x2222222222222222222222222222222222222222',
            'fromAmount': '1',
            'slippage': '0.5',
            'market': 'm',
            'protocol': 'p',
        }
        response = {
            'txs': [
                {
                    'chain': 'base',
                    'deriveTransaction': {
                        'to': '0x3333333333333333333333333333333333333333',
                        'data': '0x095ea7b300000000000000000000000000000000000000000000000000000000',
                        'value': '0x0',
                    }
                }
            ]
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            ctx = self._ctx()
            approved = tx_policy.validate_intent(ctx, intent)
            with self.assertRaisesRegex(tx_policy.PolicyError, 'approval/permit'):
                tx_policy.inspect_swap_response(ctx, approved, response)

    def test_transfer_confirm_requires_approval_token(self):
        module = load_script_module('transfer_make_sign_send.py', 'transfer_make_sign_send_test')
        argv = [
            'transfer_make_sign_send.py',
            '--chain', 'base',
            '--contract', '0x3333333333333333333333333333333333333333',
            '--from-address', '0x1111111111111111111111111111111111111111',
            '--to-address', '0x2222222222222222222222222222222222222222',
            '--amount', '1',
            '--confirm',
            '--policy-file', str(self.policy_file),
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch.object(sys, 'argv', argv), \
             mock.patch.object(module.importlib, 'import_module', side_effect=AssertionError('API should not be imported')), \
             contextlib.redirect_stdout(stdout), \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exc:
                module.main()
        self.assertEqual(exc.exception.code, 1)
        self.assertIn('Missing --approval-token', stderr.getvalue())

    def test_gasless_fallback_is_blocked_before_submit(self):
        module = load_script_module('transfer_make_sign_send.py', 'transfer_make_sign_send_gasless')
        preview_intent = {
            'operation': 'transfer',
            'walletMode': 'local',
            'chain': 'base',
            'contract': '0x3333333333333333333333333333333333333333',
            'from': '0x1111111111111111111111111111111111111111',
            'to': '0x2222222222222222222222222222222222222222',
            'amount': '1',
            'memo': '',
            'gasless': True,
            'gaslessPayToken': '',
            'override7702': False,
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            preview = tx_policy.issue_preview(self._ctx(), preview_intent)

        key_file = self.base / 'pk.txt'
        key_file.write_text('deadbeef', encoding='utf-8')
        key_file.chmod(0o600)

        class FakeAPI:
            called_submit = False

            @staticmethod
            def make_transfer_order(**kwargs):
                return {
                    'status': 0,
                    '_security_check_valid': True,
                    '_security_request_check_valid': True,
                    '_security_double_check_valid': True,
                    'data': {
                        'orderId': 'ord-2',
                        'chain': 'base',
                        'from': '0x1111111111111111111111111111111111111111',
                        'to': '0x2222222222222222222222222222222222222222',
                        'amount': '1',
                        'contract': '0x3333333333333333333333333333333333333333',
                        'source': {'type': 'evm_1559', 'evm': {'to': '0x3333333333333333333333333333333333333333', 'data': '0xa9059cbb', 'value': '0x0'}},
                        'noGas': {'available': False},
                    }
                }

            @staticmethod
            def submit_transfer_order(**kwargs):
                FakeAPI.called_submit = True
                return {'status': 0}

        argv = [
            'transfer_make_sign_send.py',
            '--chain', 'base',
            '--contract', '0x3333333333333333333333333333333333333333',
            '--from-address', '0x1111111111111111111111111111111111111111',
            '--to-address', '0x2222222222222222222222222222222222222222',
            '--amount', '1',
            '--gasless',
            '--private-key-file', str(key_file),
            '--confirm',
            '--approval-token', preview['approvalToken'],
            '--policy-file', str(self.policy_file),
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch.object(sys, 'argv', argv), \
             mock.patch.object(module.importlib, 'import_module', return_value=FakeAPI), \
             contextlib.redirect_stdout(stdout), \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exc:
                module.main()
        self.assertEqual(exc.exception.code, 1)
        self.assertFalse(FakeAPI.called_submit)
        self.assertIn('Silent fallback to a standard transfer is blocked', stderr.getvalue())

    def test_social_preview_works_without_loading_secrets(self):
        module = load_script_module('social_transfer_make_sign_send.py', 'social_transfer_make_sign_send_test')
        argv = [
            'social_transfer_make_sign_send.py',
            '--wallet-id', 'wallet-1',
            '--chain', 'sol',
            '--contract', 'So11111111111111111111111111111111111111112',
            '--from-address', '11111111111111111111111111111111',
            '--to-address', 'So11111111111111111111111111111111111111112',
            '--amount', '1',
            '--policy-file', str(self.policy_file),
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch.object(sys, 'argv', argv), \
             mock.patch.object(module.importlib, 'import_module', side_effect=AssertionError('API should not be imported in preview')), \
             contextlib.redirect_stdout(stdout), \
             contextlib.redirect_stderr(stderr):
            module.main()
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload['mode'], 'preview')
        self.assertEqual(stderr.getvalue(), '')

    def test_audit_log_redacts_secrets_and_signatures(self):
        intent = {
            'operation': 'transfer',
            'walletMode': 'local',
            'chain': 'base',
            'contract': '0x3333333333333333333333333333333333333333',
            'from': '0x1111111111111111111111111111111111111111',
            'to': '0x2222222222222222222222222222222222222222',
            'amount': '1',
        }
        with mock.patch.dict(os.environ, self.env, clear=False):
            ctx = self._ctx()
            tx_policy.write_audit_log(ctx, intent, 'preview-issued', extra={
                'mnemonic': 'secret words',
                'signature': '0xabc',
                'private_key': '0xdef',
            })
        log_text = self.audit_log.read_text(encoding='utf-8')
        self.assertIn('[REDACTED]', log_text)
        self.assertNotIn('secret words', log_text)
        self.assertNotIn('0xabc', log_text)
        self.assertNotIn('0xdef', log_text)


if __name__ == '__main__':
    unittest.main()
