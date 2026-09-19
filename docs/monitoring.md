# Secure Monitoring / المراقبة الآمنة

## English

- `scripts/monitoring.py` adds a **read-only** monitoring layer for public on-chain holdings and broader financial assets.
- Supported provider types today:
  - `evm_rpc` for EVM native / ERC-20 balances
  - `solana_rpc` for SOL / SPL balances plus last-signature activity
  - `bitget_price` for optional approximate token pricing on EVM crypto assets
  - `static` for local testing and mocks
- Internal API:
  - `GET /healthz`
  - `GET /status`
  - `GET /totals`
  - `GET /alerts`
- The internal HTTP API serves **localhost callers only** by default.
- Example commands:

```bash
python3 scripts/monitoring.py status --config /absolute/path/to/config/monitoring.example.json
python3 scripts/monitoring.py serve --config /absolute/path/to/config/monitoring.example.json
```

- Configure public RPC endpoints with `.env` values from `.env.example`.
- Replace the `BGW_MONITOR_CONFIG` example path with your own repository path before running the CLI or server.
- Config accepts modern `assets` entries and still reads legacy `wallets` entries for backward compatibility.
- Snapshots now include `asset_type`, identifier, approximate value totals, and optional `recent_history`.
- Native EVM asset pricing can use `metadata.pricing_contract` when the price source expects a wrapped-token contract.
- Non-EVM assets should use `static` or a dedicated future provider for valuation; `bitget_price` is intentionally EVM-only.
- **Do not store** private keys, seed phrases, passwords, or API secrets in JSON config files or logs.
- The monitoring flow is **observation only**. It does not sign, approve, send, or execute transactions.

## العربية

- الملف `scripts/monitoring.py` يضيف طبقة مراقبة **للقراءة فقط** للأرصدة العامة على الشبكة وللأصول المالية العامة بشكل أوسع.
- أنواع المزودات المدعومة حاليًا:
  - `evm_rpc` لأرصدة الشبكات المتوافقة مع EVM وERC-20
  - `solana_rpc` لأرصدة SOL وSPL مع آخر نشاط من RPC
  - `bitget_price` لتقدير قيمة أصول الكريبتو على شبكات EVM
  - `static` للاختبارات والمحاكاة
- الواجهة الداخلية:
  - `GET /healthz`
  - `GET /status`
  - `GET /totals`
  - `GET /alerts`
- واجهة HTTP الداخلية تسمح بطلبات **localhost فقط** بشكل افتراضي.
- أمثلة التشغيل:

```bash
python3 scripts/monitoring.py status --config /absolute/path/to/config/monitoring.example.json
python3 scripts/monitoring.py serve --config /absolute/path/to/config/monitoring.example.json
```

- استخدم `.env.example` كنموذج لقيم البيئة غير السرية فقط.
- استبدل مسار `BGW_MONITOR_CONFIG` في المثال بمسار المستودع لديك قبل التشغيل.
- الإعدادات تقبل `assets` بشكل أساسي، مع استمرار دعم `wallets` القديمة للتوافق.
- المخرجات أصبحت تعرض `asset_type` والمعرّف والإجماليات و`recent_history` عند توفرها.
- يمكن تسعير الأصل الأصلي في شبكات EVM عبر `metadata.pricing_contract` إذا كان مصدر السعر يحتاج عقدًا مماثلًا للنسخة المغلفة.
- الأصول غير EVM ينبغي أن تستخدم `static` أو مزودًا مخصصًا لاحقًا للتقييم؛ `bitget_price` مخصص حاليًا لأصول EVM فقط.
- **ممنوع** حفظ private keys أو seed phrases أو كلمات المرور أو API secrets داخل الإعدادات أو السجلات.
- النظام مخصص للمتابعة والقراءة فقط، ولا يوقّع أو ينفذ معاملات.
