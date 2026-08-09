$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$normalizedRoot = $projectRoot.Replace("\", "/")

if ($normalizedRoot -like "*/OneDrive/*") {
    throw "IncidentSeal must not run from OneDrive custody."
}

$gitRoot = (& git -C $projectRoot rev-parse --show-toplevel 2>$null).Trim().Replace("\", "/")
if ($LASTEXITCODE -ne 0 -or $gitRoot -ne $normalizedRoot) {
    throw "Git root does not match the canonical project root."
}

$requiredFiles = @(
    "AGENTS.md",
    "control/project-control.json",
    "contracts/IS-0001.json",
    "docs/product-contract.md",
    "docs/threat-model.md",
    "docs/environment-inventory.md",
    "docs/roadmap.md",
    "docs/status.md",
    "records/evidence-ledger.jsonl"
)

$missing = @()
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $relativePath))) {
        $missing += $relativePath
    }
}
if ($missing.Count -gt 0) {
    throw "Missing required project controls: $($missing -join ', ')"
}

$profile = Get-Content -Raw (Join-Path $projectRoot "control/project-control.json") | ConvertFrom-Json
$contract = Get-Content -Raw (Join-Path $projectRoot "contracts/IS-0001.json") | ConvertFrom-Json

$branch = (& git -C $projectRoot branch --show-current).Trim()
$null = & git -C $projectRoot show-ref --verify --quiet "refs/heads/$branch"
if ($LASTEXITCODE -eq 0) {
    $head = (& git -C $projectRoot rev-parse HEAD).Trim()
}
else {
    $head = $null
}

$dockerServer = (& docker version --format "{{.Server.Version}}" 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or -not $dockerServer) {
    throw "Docker server is unavailable."
}

$composeVersion = (& docker compose version --short 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or -not $composeVersion) {
    throw "Docker Compose is unavailable."
}

$result = [ordered]@{
    schema_version = "incidentseal-probe/v1"
    observed_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    project_root = $normalizedRoot
    profile_id = $profile.profile_id
    checkpoint_id = $profile.current_checkpoint.checkpoint_id
    milestone_status = $contract.status
    branch = $branch
    head = $head
    docker_server = $dockerServer
    compose = $composeVersion
    required_files = "PASS"
    custody = "PASS"
}

$result | ConvertTo-Json -Depth 4
