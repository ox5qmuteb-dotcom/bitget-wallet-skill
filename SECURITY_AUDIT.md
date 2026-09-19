# Security Audit Notes

## Added deny-by-default test coverage

The repository now includes local, offline policy tests in:

- `/home/runner/work/bitget-wallet-skill/bitget-wallet-skill/tests/test_tx_policy.py`
- `/home/runner/work/bitget-wallet-skill/bitget-wallet-skill/scripts/tx_policy.py`

### Covered controls

- Reject recipient not present in allowlist before sign/submit.
- Reject native-token transfers by default.
- Reject `approve` / `permit` (including risky calldata selectors) by default.
- Reject amounts above per-transaction / daily / session limits.
- Reject `--override-7702` by default.
- Reject submit/send without explicit preview-bound approval token.
- Validate representative EVM, Solana, and Social Login style flows.
- Validate audit-log redaction of mnemonic/private key/signature fields.

### Safety constraints in tests

- No real blockchain transactions are executed.
- No network calls are made.
- No real private keys, mnemonics, or funded addresses are used.
