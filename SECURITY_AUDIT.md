# SECURITY AUDIT

## Scope reviewed
- `scripts/`
- `docs/`
- `README.md`
- `SKILL.md`

## What was found
- Swap and transfer entrypoints previously executed `make* -> sign -> send/submit` in a single invocation without an in-code approval gate.
- There was no reusable local policy layer for address / chain / contract allowlists or per-transaction, daily, and session limits.
- Gasless transfer flows could fall back to standard transfer inside the same run after an interactive prompt.
- `--override-7702` relied on an interactive prompt, but not on an explicit local policy gate.
- EVM signing paths did not locally block approval / permit-style calldata before signing.
- There was no dedicated local audit log for preview / approval / denial / submission decisions.

## What was added / blocked
- Added `scripts/tx_policy.py` as a reusable policy gate before `makeOrder`, `makeTransferOrder`, signing, and `send` / `submitTransferOrder`.
- Added deny-by-default policy activation via `security/policy.json` (documented from `security/policy.example.json`).
- Added preview-first execution: fund-moving scripts now default to dry-run preview and emit an `approvalToken`; execution requires `--confirm --approval-token <token>` for the exact same request.
- Added chain / from / to / contract allowlists with address-format validation for EVM, Solana, and Tron.
- Added per-tx, daily, and session amount limits with automatic refusal when exceeded.
- Blocked recipient addresses outside the allowlist before signing.
- Blocked native-token transfers by default.
- Blocked approval / permit-style EVM calldata by default.
- Blocked EIP-7702 authorization by default unless explicitly enabled in policy.
- Blocked `--override-7702` by default unless explicitly enabled in policy; the warning remains permanent in execution output.
- Blocked silent gasless fallback: if gasless is unavailable, the script aborts before signing and requires a new preview without `--gasless`.
- Added local audit logging to `audit/security-audit.ndjson` with intent, chain, contract, from/to, amount, policy decision, orderId, and timestamps.
- Audit log redacts mnemonic / private key / secret / signature fields.

## What was not found
- No casino / gambling component was found in the repository review. A repo-wide search for `casino`, `gambl`, `bet`, `roulette`, `slot`, `wager`, and `poker` produced no functional gambling module to harden or redirect.

## Breaking change / migration
- One-shot scripts no longer sign or submit by default.
- New flow:
  1. Copy `security/policy.example.json` to `security/policy.json`
  2. Edit allowlists and limits
  3. Run the desired one-shot script without `--confirm` to get a preview + `approvalToken`
  4. Re-run the exact same command with `--confirm --approval-token <token>`

## Validation performed
- Added focused `unittest` coverage for:
  - EVM recipient allowlist enforcement
  - native transfer blocking
  - daily limit enforcement
  - approval-calldata blocking
  - approval-token requirement before submit
  - gasless fallback blocking
  - Social Login preview flow
  - audit-log secret redaction

## Remaining limits / caveats
- EVM mixed-case checksum validation uses `eth_utils` when available; without it, lowercase / uppercase hex addresses are accepted and mixed-case addresses are rejected.
- The local policy model is intentionally strict and may block existing flows until router / token / recipient allowlists are populated.
- The audit log tracks local policy decisions only; it does not replace external chain monitoring or backend-side security controls.
