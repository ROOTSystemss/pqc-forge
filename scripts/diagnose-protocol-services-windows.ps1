$ErrorActionPreference = 'Continue'

$projectRoot = Split-Path $PSScriptRoot -Parent
$docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$compose = Join-Path $projectRoot 'lab\compose.yml'
$logPath = Join-Path $projectRoot 'protocol-services-diagnostic.log'
$common = @('compose', '-f', $compose, '--project-name', 'pqc-forge-lab')

Set-Location $projectRoot
& $docker @common up -d classical-rsa hybrid-rsa pqonly-rsa hybrid-mldsa *>&1 | Tee-Object -FilePath $logPath
& $docker @common ps --all *>&1 | Tee-Object -FilePath $logPath -Append
& $docker @common logs --no-color *>&1 | Tee-Object -FilePath $logPath -Append
& $docker @common down --volumes --remove-orphans *>&1 | Tee-Object -FilePath $logPath -Append
