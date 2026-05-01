# QRAE Phase 1 Operational Upgrade — File Manifest

Drop these files into the repository root, replacing files with the same paths.

## Replaced / updated

- README.md
- pyproject.toml
- qrae/__init__.py
- qrae/__main__.py
- qrae/cli.py
- qrae/core/__init__.py
- qrae/core/audit.py
- qrae/core/classifier.py
- qrae/core/models.py
- qrae/core/scope.py
- qrae/protocols/__init__.py
- qrae/protocols/channel.py
- qrae/protocols/tls.py

## New

- qrae/core/risk.py
- qrae/core/signing.py
- qrae/protocols/tls_deep.py
- qrae/protocols/x509_chain.py
- qrae/protocols/ssh.py
- qrae/protocols/code_scan.py
- qrae/reports/__init__.py
- qrae/reports/render.py
- tests/test_classifier_policy.py
- tests/test_risk.py
- tests/test_code_scan.py
- tests/test_tls_deep_parse.py
- tests/test_scope.py
- tests/test_report.py

## Main new commands

```bash
qrae tls scan example.org --deep --out findings-tls.json
qrae ssh scan example.org --out findings-ssh.json
qrae code scan ./infra --out findings-code.json
qrae report markdown findings-tls.json findings-ssh.json --out qrae-report.md
qrae report sarif findings-tls.json findings-ssh.json --out qrae-report.sarif.json
qrae sign keygen --private-key private.pem --public-key public.pem
qrae sign file qrae-report.md --private-key private.pem
qrae sign verify qrae-report.md --signature qrae-report.md.sig.json --public-key public.pem
```
