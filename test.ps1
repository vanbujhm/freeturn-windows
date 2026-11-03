# Запускает все проверки: go vet, go test и тесты интерфейса. Останавливается на первой ошибке.
#requires -Version 7
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:CGO_ENABLED = '0'

function Invoke-Step {
    param([string]$Title, [scriptblock]$Command)
    Write-Host "== $Title"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Title завершилась с кодом $LASTEXITCODE" }
}

Invoke-Step 'go vet' { go vet ./... }
Invoke-Step 'go test' { go test -count=1 ./... }
Push-Location -LiteralPath (Join-Path $PSScriptRoot 'frontend')
try {
    Invoke-Step 'vitest' { npx vitest run }
}
finally {
    Pop-Location
}
Write-Host 'Все проверки прошли'
