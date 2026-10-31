# Запускает тесты, которым нужны права администратора (тег admin).
# Скрипт идёт в отдельном окне с повышением прав, поэтому вывод пишется в файл,
# путь к которому передаётся первым аргументом. Код выхода не нулевой при провале.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$OutFile
)

$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $PSScriptRoot

$packages = @('./internal/netcfg', './internal/tunnel', './internal/firewall') |
    Where-Object { Test-Path -LiteralPath $_ -PathType Container }

if (-not $packages) {
    'Нет пакетов для проверки' | Out-File -LiteralPath $OutFile -Encoding utf8
    exit 1
}

$env:CGO_ENABLED = '0'
# Вывод go test идёт в файл целиком, включая ошибки сборки.
& go test -count=1 -v -tags admin @packages *> $OutFile
$code = $LASTEXITCODE
"exit code: $code" | Out-File -LiteralPath $OutFile -Append -Encoding utf8
exit $code
