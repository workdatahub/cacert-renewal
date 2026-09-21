# CA Certificate Renewal

This repository automatically tracks the CA certificate chains required by HomeControler.

## Monitored domains

See [domains.list](./domains.list).

## Generated files

For each domain:

- `cert/<domain>.intermediate0.pem`
- `cert/<domain>.intermediate1.pem`
- ...
- `cert/<domain>.root.pem`

Each certificate has a matching serial-number-only file under `info/`.

The GitHub Actions workflow checks the monitored TLS endpoints daily and can also be started manually with **Actions → Update CA certificates → Run workflow**.

Only CA certificates are published. The server/leaf certificate is intentionally not stored.
