param(
    [ValidatePattern('^[0-9]+$')][string]$RunId,
    [Parameter(Mandatory)][string]$Destination
)

$ErrorActionPreference = 'Stop'
$repository = 'LeiSureLyYrsc/foundation-panel-kanade'
$branch = 'kanade/tray-online-mode-462c3853'
$artifactName = 'sunshine-gui-windows-x64'
$trayUiUrl = 'https://codeload.github.com/LeiSureLyYrsc/foundation-ui-kanade/tar.gz/0c31795efebc48ee68c17d0ff6d23fe4ad8309e8'
$trayUiIntegrity = 'sha512-TO+3O+VFlXzPmH/l7EgVdfLTP4W60vnmcwRtI+KDbQevpVQrRNAn7qQLsMZFgAAsRCvreD7HuyCMxx000sU5Hg=='
$panelPath = 'src_assets/common/sunshine-control-panel'
$configuredUrl = git config --blob HEAD:.gitmodules --get "submodule.$panelPath.url"
if ($LASTEXITCODE -ne 0 -or $configuredUrl -cne "https://github.com/$repository.git") {
    throw 'The committed Panel submodule URL does not match the authorized artifact source'
}
$entry = git ls-tree HEAD $panelPath
if ($LASTEXITCODE -ne 0 -or $entry -notmatch '^160000 commit ([0-9a-f]{40})\s') {
    throw 'Unable to resolve the committed Panel submodule'
}
$expectedCommit = $Matches[1]

function Test-PairedRun($Run) {
    $Run.conclusion -ceq 'success' -and $Run.status -ceq 'completed' -and
        $Run.repository.full_name -ceq $repository -and $Run.head_repository.full_name -ceq $repository -and
        $Run.head_branch -ceq $branch -and $Run.head_sha -ceq $expectedCommit -and
        $Run.path -ceq '.github/workflows/build.yml' -and $Run.event -ceq 'workflow_dispatch'
}

function Get-PairedArtifacts([string]$Id) {
    $json = gh api "repos/$repository/actions/runs/$Id/artifacts?per_page=100"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect paired Panel artifacts' }
    ($json | ConvertFrom-Json).artifacts | Where-Object { $_.name -ceq $artifactName -and -not $_.expired }
}

if (-not $RunId) {
    $runsJson = gh api "repos/$repository/actions/workflows/build.yml/runs?head_sha=$expectedCommit&status=success&per_page=100"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to discover paired Panel builds' }
    foreach ($candidate in ($runsJson | ConvertFrom-Json).workflow_runs) {
        if ((Test-PairedRun $candidate) -and @(Get-PairedArtifacts $candidate.id).Count -eq 1) {
            $RunId = [string]$candidate.id
            break
        }
    }
    if (-not $RunId) {
        throw "No successful, unexpired GUI artifact for Panel $expectedCommit. Build that Panel commit before packaging this release."
    }
}
$runJson = gh api "repos/$repository/actions/runs/$RunId"
if ($LASTEXITCODE -ne 0) { throw 'Unable to read the Panel workflow run' }
$run = $runJson | ConvertFrom-Json
if (-not (Test-PairedRun $run)) {
    throw "Panel run must be a successful build.yml dispatch from $repository/$branch at $expectedCommit"
}
$artifacts = @(Get-PairedArtifacts $RunId)
if ($artifacts.Count -ne 1) { throw "Expected exactly one unexpired $artifactName artifact in run $RunId" }
$artifact = $artifacts[0]
if ([string]$artifact.workflow_run.id -cne $RunId -or $artifact.workflow_run.head_sha -cne $expectedCommit -or
    $artifact.workflow_run.repository_id -ne $run.repository.id -or
    $artifact.workflow_run.head_repository_id -ne $run.head_repository.id) {
    throw 'Panel artifact metadata does not agree with the verified run'
}

# Read the lock at the exact run commit without executing or checking out Panel source.
$lockJson = gh api --method GET "repos/$repository/contents/package-lock.json" -f "ref=$expectedCommit" -H 'Accept: application/vnd.github.raw+json'
if ($LASTEXITCODE -ne 0) { throw 'Unable to read the committed Panel lockfile' }
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $lock = ($lockJson -join "`n") | ConvertFrom-Json -AsHashtable
} else {
    # Windows PowerShell cannot represent the npm lockfile's empty root key as a property.
    Add-Type -AssemblyName System.Web.Extensions
    $lock = [System.Web.Script.Serialization.JavaScriptSerializer]::new().DeserializeObject(($lockJson -join "`n"))
}
$packages = $lock['packages']
$trayUi = $packages['node_modules/foundation-ui']
if ($packages['']['dependencies']['foundation-ui'] -cne $trayUiUrl -or
    $trayUi['resolved'] -cne $trayUiUrl -or $trayUi['integrity'] -cne $trayUiIntegrity) {
    throw 'The Panel lockfile does not pin the expected foundation-ui tray source and SHA-512 integrity'
}

# Keep the executable and its native plugin on one build boundary. Never use
# individual files from another release to fill gaps in this bundle.
if (Test-Path -LiteralPath $Destination) {
    throw 'Choose a fresh destination for the paired GUI bundle'
}
$download = Join-Path ([IO.Path]::GetTempPath()) ('paired-gui-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $download | Out-Null
gh run download $RunId --repo $repository --name $artifactName --dir $download
if ($LASTEXITCODE -ne 0) { throw "Unable to download Panel artifact; diagnostic files: $download" }
$archive = Join-Path $download "$artifactName.zip"
Expand-Archive -LiteralPath $archive -DestinationPath $Destination
foreach ($name in @('sunshine-gui.exe', 'alkaidlab-plugin-stylus.dll')) {
    $file = Get-Item -LiteralPath (Join-Path $Destination $name)
    if ($file.PSIsContainer -or $file.Length -eq 0) { throw "Invalid required GUI file: $name" }
}
[ordered]@{
    repository = $repository
    run_id = $RunId
    run_attempt = $run.run_attempt
    commit = $expectedCommit
    artifact_id = $artifact.id
    bundle_sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    tray_foundation_ui_url = $trayUiUrl
    tray_foundation_ui_integrity = $trayUiIntegrity
} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Destination 'paired-build.json') -Encoding utf8
Write-Output "Paired GUI bundle verified at $expectedCommit in $Destination"
