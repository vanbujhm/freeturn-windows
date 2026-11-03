# Собирает интерфейс, FreeTurn.exe, FreeTurnService.exe и установщик.
#
#   pwsh -File build.ps1 [-Version 0.9.0] [-UpdateRepo владелец/репозиторий] [-Iscc путь] [-SkipInstaller]
#
# Без -Version номер берётся из файла VERSION в корне репозитория.
#
# Результат: build\FreeTurn.exe, build\FreeTurnService.exe, build\wintun.dll и
# dist\FreeTurnSetup-<версия>.exe. С -SkipInstaller сборка останавливается после build\,
# Inno Setup для этого не нужен.
#requires -Version 7
param(
    # Номер версии. Пусто: берётся из файла VERSION.
    [string]$Version = '',
    # Репозиторий GitHub для проверки новой версии. Пусто: проверка выключена.
    [string]$UpdateRepo = '',
    # Путь к ISCC.exe. Без него ищется в Program Files.
    [string]$Iscc = '',
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $Version) { $Version = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'VERSION') -TotalCount 1).Trim() }
# Ядро и все пакеты собираются без cgo: gcc на машине сборки не нужен.
$env:CGO_ENABLED = '0'

# Закреплённые сторонние файлы. Всё скачанное проверяется по хэшу.
$WintunSha256 = '5e31cdae7d2e7b5e5daa32455e7742312a94b50573f7ac429dbc4bdfb829c79e'
$WintunSigner = 'WireGuard LLC'
$WebView2Sha256 = 'cf2f2445fef0c5c14e372045f84998771eeb8bb01d59be4afd00692fa160082e'
$WebView2Signer = 'Microsoft Corporation'
# Inno Setup ставит человек сам. Хэш относится к файлу установки версии 7.1.1: он совпадает с
# SHA-256 в карточке релиза на GitHub. Файл подписан Pyrsys B.V., издателем Inno Setup.
$InnoSetupVersion = '7.1.1'
$InnoSetupUrl = 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe'
$InnoSetupSha256 = '8a5a6711c3766a6e5fb74f280ba0e3551e719ce94538d901fdbd1f8f9920b3f0'

function Invoke-Native {
    param([string]$Title, [scriptblock]$Command)
    Write-Host "== $Title"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Title завершилась с кодом $LASTEXITCODE" }
}

# Проверяет хэш и подпись файла. Подпись должна быть действительной и принадлежать издателю.
function Assert-Trusted {
    param([string]$Path, [string]$Sha256, [string]$Signer)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Нет файла $Path" }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) { throw "Хэш $Path не совпадает: ожидался $Sha256, получен $actual" }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') { throw "Подпись $Path недействительна: $($sig.Status)" }
    if ($sig.SignerCertificate.Subject -notlike "*CN=$Signer*") {
        throw "$Path подписан не $Signer, а $($sig.SignerCertificate.Subject)"
    }
}

function Find-Iscc {
    if ($Iscc) {
        if (-not (Test-Path -LiteralPath $Iscc -PathType Leaf)) { throw "Нет файла ISCC.exe: $Iscc" }
        return (Resolve-Path -LiteralPath $Iscc).Path
    }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 7\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 7\ISCC.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    }
    throw @"
Не найден ISCC.exe из Inno Setup 7. Искал здесь:
  $($candidates -join "`n  ")
Установите Inno Setup $InnoSetupVersion или укажите путь ключом -Iscc.
Файл установки: $InnoSetupUrl
SHA-256: $InnoSetupSha256
Чтобы собрать только exe, запустите с ключом -SkipInstaller.
"@
}

function Find-Wails {
    $cmd = Get-Command wails3 -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $path = Join-Path $env:USERPROFILE 'go\bin\wails3.exe'
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    throw 'Не найден wails3. Установите: go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0'
}

# Версия и репозиторий попадают в ldflags, поэтому принимаются только простые значения.
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Версия должна быть вида 1.2.3, получено: $Version" }
if ($UpdateRepo -and $UpdateRepo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "Репозиторий должен быть вида владелец/имя, получено: $UpdateRepo"
}

# Всё, что может не найтись, проверяется до долгой сборки.
Assert-Trusted 'third_party\wintun\wintun.dll' $WintunSha256 $WintunSigner
$wails = Find-Wails
if (-not $SkipInstaller) {
    $isccPath = Find-Iscc
    Assert-Trusted 'third_party\webview2\MicrosoftEdgeWebview2Setup.exe' $WebView2Sha256 $WebView2Signer
}

Invoke-Native 'wails3 generate bindings' {
    & $wails generate bindings -d frontend/bindings -ts ./cmd/freeturn
}
Push-Location -LiteralPath (Join-Path $PSScriptRoot 'frontend')
try {
    Invoke-Native 'npm ci' { npm ci }
    Invoke-Native 'npm run build' { npm run build }
}
finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path 'build' | Out-Null
Remove-Item -LiteralPath 'build\FreeTurn.exe', 'build\FreeTurnService.exe', 'build\wintun.dll' -Force -ErrorAction SilentlyContinue

# Окно без консоли: -H=windowsgui. Тег devconsole в выпуск не входит никогда.
$guiFlags = "-s -w -H=windowsgui -X main.version=$Version -X main.updateRepo=$UpdateRepo"
Invoke-Native 'go build FreeTurn.exe' {
    go build -trimpath -ldflags $guiFlags -o build/FreeTurn.exe ./cmd/freeturn
}
Invoke-Native 'go build FreeTurnService.exe' {
    go build -trimpath -ldflags '-s -w' -o build/FreeTurnService.exe ./cmd/freeturn-service
}
Copy-Item -LiteralPath 'third_party\wintun\wintun.dll' -Destination 'build\wintun.dll'

if ($SkipInstaller) {
    Write-Host 'Установщик пропущен (-SkipInstaller). Файлы в build\'
    return
}

New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
Invoke-Native 'ISCC' {
    & $isccPath "/DAppVersion=$Version" "/DRepoDir=$PSScriptRoot" (Join-Path $PSScriptRoot 'installer\freeturn.iss')
}
Write-Host "Готово: dist\FreeTurnSetup-$Version.exe"
