# Run the same checks as CI locally
Write-Host "=== ruff ==="
python -m ruff check codeaudit tests
Write-Host "`n=== mypy ==="
python -m mypy codeaudit --ignore-missing-imports
Write-Host "`n=== pytest + coverage ==="
python -m pytest tests/ --cov=codeaudit --cov-report=term
Write-Host "`n=== self-scan ==="
codeaudit scan codeaudit/
