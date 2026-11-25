[CmdletBinding()]
param(
    [switch]$Docker
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function New-LocalSecret {
    $bytes = New-Object byte[] 48
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Initialize-LocalFiles {
    if (-not (Test-Path ".env")) {
        $contents = [System.IO.File]::ReadAllText((Join-Path $root ".env.example"))
        $contents = $contents.Replace("replace-with-a-local-only-password", (New-LocalSecret))
        $contents = $contents.Replace("replace-with-a-generated-local-secret", (New-LocalSecret))
        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText((Join-Path $root ".env"), $contents, $encoding)
        Write-Host "Created .env with newly generated local-only secrets."
    }
    else {
        $contents = [System.IO.File]::ReadAllText((Join-Path $root ".env"))
        if (
            $contents.Contains("replace-with-a-local-only-password") -or
            $contents.Contains("replace-with-a-generated-local-secret")
        ) {
            throw ".env contains example placeholders. Replace them locally; setup will not overwrite an existing .env."
        }
    }

    $localConfig = Join-Path $root "config\ciclosec.yaml"
    if (-not (Test-Path $localConfig)) {
        Copy-Item (Join-Path $root "config\ciclosec.yaml.example") $localConfig
        Write-Host "Created config\ciclosec.yaml without enabling on-demand scans."
    }
}

function Get-DockerCommand {
    $command = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Docker CLI is required. Install Docker Desktop or Docker Engine with Compose, then rerun setup."
    }
    if ((Invoke-NativeQuiet $command.Source @("info")) -ne 0) {
        throw "Docker is installed but its daemon is unavailable. Start Docker Desktop/Engine and rerun setup."
    }
    Invoke-Checked $command.Source @("compose", "version") | Out-Host
    return $command.Source
}

function Invoke-NativeQuiet {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Program @Arguments 2>&1 | Out-Null
        $result = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    return $result
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $Program @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    foreach ($line in $output) {
        Write-Output $line
    }
    if ($exitCode -ne 0) {
        throw "$Program $($Arguments -join ' ') failed with exit code $exitCode."
    }
}

function Wait-For-LocalServices {
    param([string]$DockerCommand)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $postgresExit = Invoke-NativeQuiet $DockerCommand @(
            "compose", "exec", "-T", "postgres", "sh", "-c",
            'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
        )
        $redisExit = Invoke-NativeQuiet $DockerCommand @(
            "compose", "exec", "-T", "redis", "redis-cli", "ping"
        )
        $postgresReady = $postgresExit -eq 0
        $redisReady = $redisExit -eq 0
        if ($postgresReady -and $redisReady) {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "PostgreSQL and Redis did not become ready. Inspect them with 'docker compose ps' and 'docker compose logs postgres redis'."
}

function Install-Uv {
    $existing = Get-Command uv -ErrorAction SilentlyContinue
    if ($existing) {
        return $existing.Source
    }

    $installer = Join-Path $env:TEMP ("uv-install-" + [Guid]::NewGuid().ToString("N") + ".ps1")
    try {
        [Net.ServicePointManager]::SecurityProtocol = (
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        )
        Invoke-WebRequest -Uri "https://astral.sh/uv/install.ps1" -OutFile $installer
        $powershell = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if (-not $powershell) {
            $powershell = Get-Command pwsh.exe -ErrorAction Stop
        }
        Invoke-Checked $powershell.Source @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installer
        )
    }
    finally {
        if (Test-Path $installer) {
            Remove-Item -LiteralPath $installer -Force
        }
    }

    foreach ($candidate in @(
        (Join-Path $HOME ".local\bin\uv.exe"),
        (Join-Path $HOME ".cargo\bin\uv.exe")
    )) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    throw "uv installation finished but uv.exe was not found in the standard user install directories."
}

Initialize-LocalFiles
$dockerCommand = Get-DockerCommand

if ($Docker) {
    Invoke-Checked $dockerCommand @("compose", "--profile", "app", "up", "--build", "-d")
    $webReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $webExit = Invoke-NativeQuiet $dockerCommand @(
            "compose", "exec", "-T", "web", "python", "-c",
            "import socket; socket.create_connection(('127.0.0.1', 8000), timeout=2).close()"
        )
        if ($webExit -eq 0) {
            $webReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    $workerReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $workerLogs = @(Invoke-Checked $dockerCommand @(
            "compose", "--profile", "app", "logs", "--no-color", "--tail", "100", "worker"
        ))
        if ($workerLogs -match "ready\.") {
            $workerReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $workerReady) {
        throw "The Docker worker did not report readiness. Inspect 'docker compose --profile app logs worker'."
    }
    Invoke-Checked $dockerCommand @("compose", "--profile", "app", "exec", "-T", "worker", "trivy", "--version")
    Invoke-Checked $dockerCommand @("compose", "--profile", "app", "exec", "-T", "worker", "osv-scanner", "--version")
    Invoke-Checked $dockerCommand @("compose", "--profile", "app", "exec", "-T", "web", "python", "manage.py", "check")
    Invoke-Checked $dockerCommand @("compose", "--profile", "app", "ps")
    if (-not $webReady) {
        throw "The Docker web service did not become ready. Inspect 'docker compose --profile app logs web worker migrate'."
    }
    $webPortSetting = Get-Content .env | Where-Object { $_ -match '^CICLOSEC_WEB_PORT=' } | Select-Object -First 1
    $webPort = if ($webPortSetting) { $webPortSetting -replace '^CICLOSEC_WEB_PORT=', '' } else { "8000" }
    Write-Host "Docker setup is ready at http://127.0.0.1:$webPort/"
    Write-Host "Create a local account with: docker compose exec web python manage.py createsuperuser"
    exit 0
}

$uvCommand = Install-Uv
$env:PATH = "$(Split-Path -Parent $uvCommand);$env:PATH"
Invoke-Checked $uvCommand @("python", "install", "3.12")
Invoke-Checked $uvCommand @("sync", "--locked")
Invoke-Checked $uvCommand @("run", "--no-sync", "python", "scripts/install_scanners.py")

Invoke-Checked $dockerCommand @("compose", "up", "-d", "postgres", "redis")
Wait-For-LocalServices $dockerCommand
Invoke-Checked $uvCommand @("run", "--no-sync", "python", "manage.py", "migrate", "--noinput")
Invoke-Checked $uvCommand @("run", "--no-sync", "python", "manage.py", "check")

Write-Host "Native setup is ready. Python dependencies and scanners are installed in the project environment."
Write-Host "Start the web process with: uv run python manage.py runserver 127.0.0.1:8000"
Write-Host "Start a Windows worker with: uv run celery -A ciclosec.project.celery:app worker --loglevel INFO --pool solo"
Write-Host "Create a local account with: uv run python manage.py createsuperuser"
