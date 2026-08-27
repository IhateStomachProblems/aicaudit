# Run the same checks as CI locally
Write-Host "=== ruff ==="
python -m ruff check aicaudit tests
Write-Host "`n=== mypy ==="
python -m mypy aicaudit --ignore-missing-imports
Write-Host "`n=== pytest + coverage ==="
python -m pytest tests/ --cov=aicaudit --cov-report=term
Write-Host "`n=== self-scan ==="
aicaudit scan aicaudit/
