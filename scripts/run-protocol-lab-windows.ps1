$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
$nodeBin = 'C:\Program Files\nodejs'
$env:PATH = "$dockerBin;$nodeBin;$env:PATH"
$logPath = Join-Path $projectRoot 'protocol-lab-run.log'

Set-Location $projectRoot
try {
  & (Join-Path $nodeBin 'npm.cmd') run lab:protocol *>&1 | Tee-Object -FilePath $logPath
  exit $LASTEXITCODE
} catch {
  $_ | Out-String | Tee-Object -FilePath $logPath -Append | Write-Host
  exit 1
}
