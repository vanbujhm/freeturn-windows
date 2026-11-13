# Проба NRPT: применяет ли Dnscache правило для "." сразу после записи ключа и что для этого
# нужно. Запускать в PowerShell от администратора. На несколько секунд DNS машины уходит на
# 127.0.0.53, где никто не слушает. Ключ снимается в finally.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
$key = Join-Path $base ('{FreeTurn-' + [guid]::NewGuid() + '}')
$names = [System.Collections.Queue]::new(@('example.org', 'example.net', 'iana.org', 'www.example.com', 'www.iana.org'))

function Probe([string]$label) {
    $name = $names.Dequeue()
    $rule = Get-DnsClientNrptPolicy | Where-Object { $_.Namespace -eq '.' -and $_.NameServers -contains '127.0.0.53' }
    $ok = $false
    $t = Measure-Command {
        $ok = $null -ne (Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue)
    }
    '{0}: правило в действующей политике: {1}; {2} разрешился: {3} за {4:N1} с' -f $label, [bool]$rule, $name, $ok, $t.TotalSeconds
}

try {
    Probe 'до записи'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name Name -PropertyType MultiString -Value @('.') | Out-Null
    New-ItemProperty -Path $key -Name GenericDNSServers -PropertyType String -Value '127.0.0.53' | Out-Null
    New-ItemProperty -Path $key -Name ConfigOptions -PropertyType DWord -Value 8 | Out-Null
    New-ItemProperty -Path $key -Name Version -PropertyType DWord -Value 2 | Out-Null
    Probe 'сразу после записи'
    Start-Sleep -Seconds 2
    Probe 'через 2 с'
    Clear-DnsClientCache
    Probe 'после Clear-DnsClientCache'
}
finally {
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache
    Probe 'после снятия ключа'
}
