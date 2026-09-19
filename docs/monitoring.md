# Secure Monitoring / المراقبة الآمنة

## English

- `scripts/monitoring.py` adds a **read-only** monitoring layer for public wallet addresses only.
- Supported provider types today:
  - `evm_rpc` for EVM native / ERC-20 balances
  - `solana_rpc` for SOL / SPL balances plus last-signature activity
  - `bitget_price` for optional approximate token pricing
  - `static` for local testing and mocks
- Internal API:
  - `GET /healthz`
  - `GET /status`
- Example commands:

```bash
python3 scripts/monitoring.py status --config /absolute/path/to/config/monitoring.example.json
python3 scripts/monitoring.py serve --config /absolute/path/to/config/monitoring.example.json
```

- Configure public RPC endpoints with `.env` values from `.env.example`.
- **Do not store** private keys, seed phrases, passwords, or API secrets in JSON config files or logs.
- The monitoring flow is **observation only**. It does not sign, approve, send, or execute transactions.

## العربية

- الملف `scripts/monitoring.py` يضيف طبقة مراقبة **للقراءة فقط** لعناوين المحافظ العامة.
- أنواع المزودات المدعومة حاليًا:
  - `evm_rpc` لأرصدة الشبكات المتوافقة مع EVM وERC-20
  - `solana_rpc` لأرصدة SOL وSPL مع آخر نشاط من RPC
  - `bitget_price` لتقدير القيمة عند توفر مصدر مناسب
  - `static` للاختبارات والمحاكاة
- الواجهة الداخلية:
  - `GET /healthz`
  - `GET /status`
- أمثلة التشغيل:

```bash
python3 scripts/monitoring.py status --config /absolute/path/to/config/monitoring.example.json
python3 scripts/monitoring.py serve --config /absolute/path/to/config/monitoring.example.json
```

- استخدم `.env.example` كنموذج لقيم البيئة غير السرية فقط.
- **ممنوع** حفظ private keys أو seed phrases أو كلمات المرور أو API secrets داخل الإعدادات أو السجلات.
- النظام مخصص للمتابعة والقراءة فقط، ولا يوقّع أو ينفذ معاملات.
