# Threat Origin Map — one-command install / update for Windows (Docker Desktop).
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
# Re-run it any time to update; your settings (in the Docker volume) are kept.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "Hata: $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die 'Docker Desktop bulunamadı. Kurun: https://www.docker.com/products/docker-desktop/ ve tekrar çalıştırın.'
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Die 'Docker Desktop çalışmıyor. Açıp tekrar deneyin.' }

if (-not (Test-Path .env)) {
    $port = Read-Host 'Syslog UDP portu [5514]'
    if (-not $port) { $port = '5514' }
    if ($port -notmatch '^\d+$') { Die 'Port bir sayı olmalı.' }
    @(
        '# Written by install.ps1. Everything else is set in the web UI.'
        "SYSLOG_PORT=$port"
        'EVE_DIR=./eve'
        'HTTP_BIND=0.0.0.0'
        'HTTP_PORT=9595'
    ) | Set-Content -Encoding ascii .env
}
New-Item -ItemType Directory -Force eve | Out-Null
$envs = @{}; Get-Content .env | Where-Object { $_ -match '^\w+=' } | ForEach-Object { $k, $v = $_ -split '=', 2; $envs[$k] = $v }

Say 'İmaj hazırlanıyor ve başlatılıyor…'
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Die 'docker compose başarısız oldu.' }

Say 'Servisin açılması bekleniyor…'
for ($i = 0; $i -lt 60; $i++) {
    if ((docker compose logs attack-map 2>$null) -match 'Attack map on') { break }
    Start-Sleep 1
}

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet|WSL' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
if (-not $ip) { $ip = 'localhost' }
$code = ((docker compose logs attack-map 2>$null) | Select-String 'SETUP CODE: ([A-F0-9-]+)' | Select-Object -Last 1).Matches.Groups[1].Value

Write-Host ''
Write-Host 'Kurulum tamam.' -ForegroundColor Green
Write-Host "  Harita adresi : http://${ip}:$($envs.HTTP_PORT)"
Write-Host "  Syslog hedefi : ${ip}:$($envs.SYSLOG_PORT) (UDP)"
if ($code) {
    Write-Host "  Kurulum kodu  : $code"
    Write-Host ''
    Write-Host '  Adresi tarayıcıda açın, kurulum kodunu girin ve gerisini ekrandan ayarlayın.'
    Start-Process "http://localhost:$($envs.HTTP_PORT)/setup"
} else {
    Write-Host '  Kurulum daha önce tamamlanmış; ayarlarınız korundu.'
}
Write-Host ''
Write-Host '  Not: Windows güvenlik duvarında bu portlara izin vermeniz gerekebilir.'
