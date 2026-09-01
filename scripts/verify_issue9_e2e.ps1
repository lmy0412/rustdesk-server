[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientRepo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsWindowsPlatform = $env:OS -eq 'Windows_NT'
$script:FixtureRoot = $null
$script:ServerProcess = $null
$script:ServiceProcess = $null
$script:ProducerProcess = $null
$script:FlutterProcess = $null
$script:HttpClient = $null

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Protect-PrivateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($script:IsWindowsPlatform) {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
        $directory = [System.IO.DirectoryInfo]::new($Path)
        $directory.SetAccessControl($security)
    }
    else {
        & chmod 700 -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw '无法把 fixture 根目录权限设为 0700'
        }
    }
}

function Protect-PrivateFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $script:IsWindowsPlatform) {
        & chmod 600 -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "无法把私有文件权限设为 0600：$Path"
        }
    }
}

function Assert-PrivateWindowsAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $script:IsWindowsPlatform) {
        return
    }
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([System.IO.Directory]::Exists($Path)) {
        $acl = [System.IO.DirectoryInfo]::new($Path).GetAccessControl()
    }
    else {
        $acl = [System.IO.FileInfo]::new($Path).GetAccessControl()
    }
    $ownerSid = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    if ($ownerSid -ne $currentSid) {
        throw "私有路径 owner 不是当前用户：$Path"
    }
    $ownerRightsSid = 'S-1-3-4'
    $allowedAceCount = 0
    foreach ($access in $acl.Access) {
        $sid = $access.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        if (($sid -ne $currentSid -and $sid -ne $ownerRightsSid) -or
            $access.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow) {
            throw "私有路径存在当前用户之外的 DACL：$Path"
        }
        $allowedAceCount++
    }
    if ($allowedAceCount -eq 0) {
        throw "私有路径缺少 owner-only DACL：$Path"
    }
}

function Write-PrivateJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    $leaf = [System.IO.Path]::GetFileName($Path)
    $temporaryPath = Join-Path $directory (
        ".$leaf.$([Guid]::NewGuid().ToString('N')).tmp"
    )
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $json,
            [System.Text.UTF8Encoding]::new($false)
        )
        Protect-PrivateFile -Path $temporaryPath
        [System.IO.File]::Move($temporaryPath, $Path)
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}

function Wait-PrivateFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [System.Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 180
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not [System.IO.File]::Exists($Path)) {
        if ($null -ne $Process) {
            $Process.Refresh()
            if ($Process.HasExited) {
                throw "等待私有 barrier 时子进程提前退出：$([System.IO.Path]::GetFileName($Path))，PID $($Process.Id)"
            }
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "等待私有 barrier 超时：$([System.IO.Path]::GetFileName($Path))"
        }
        Start-Sleep -Milliseconds 50
    }
    Protect-PrivateFile -Path $Path
}

function Start-LoggedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogPrefix
    )
    $stdout = Join-Path $script:FixtureRoot "$LogPrefix.stdout.log"
    $stderr = Join-Path $script:FixtureRoot "$LogPrefix.stderr.log"
    $start = @{
        FilePath               = $Executable
        ArgumentList           = $Arguments
        WorkingDirectory       = $WorkingDirectory
        RedirectStandardOutput = $stdout
        RedirectStandardError  = $stderr
        PassThru               = $true
    }
    if ($script:IsWindowsPlatform) {
        $start.WindowStyle = 'Hidden'
    }
    $process = Start-Process @start
    Protect-PrivateFile -Path $stdout
    Protect-PrivateFile -Path $stderr
    return $process
}

function Wait-SuccessfulExit {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 240,
        [Parameter(Mandatory = $true)][string]$Role
    )
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "$Role 进程退出超时"
    }
    $Process.Refresh()
    $exitCode = $Process.ExitCode
    if ($null -ne $exitCode -and [int]$exitCode -ne 0) {
        throw "$Role 进程失败，退出码 $exitCode"
    }
}

function Stop-TrackedProcess {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) {
        return
    }
    try {
        $Process.Refresh()
        if ($Process.HasExited) {
            return
        }
        if ($script:IsWindowsPlatform) {
            & taskkill.exe /PID $Process.Id /T /F *> $null
        }
        else {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        # finally 清理必须继续，且不输出可能包含敏感正文的子进程日志。
    }
}

function New-HttpClient {
    Add-Type -AssemblyName System.Net.Http
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    return [System.Net.Http.HttpClient]::new($handler)
}

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [AllowNull()][string]$Token,
        [AllowNull()]$Body
    )
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method),
        $Url
    )
    try {
        if (-not [string]::IsNullOrEmpty($Token)) {
            $request.Headers.Authorization =
                [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
        }
        if ($null -ne $Body) {
            $request.Content = [System.Net.Http.StringContent]::new(
                [string]$Body,
                [System.Text.Encoding]::UTF8,
                'application/json'
            )
        }
        $response = $script:HttpClient.SendAsync($request).GetAwaiter().GetResult()
        try {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $contentType = $null
            if ($null -ne $response.Content.Headers.ContentType) {
                $contentType = $response.Content.Headers.ContentType.ToString()
            }
            return [pscustomobject]@{
                Status      = [int]$response.StatusCode
                Body        = $responseBody
                ContentType = $contentType
            }
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $request.Dispose()
    }
}

function Login-Api {
    param(
        [Parameter(Mandatory = $true)][string]$ApiBase,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password
    )
    $body = @{
        username  = $Username
        password  = $Password
        type      = 'account'
        autoLogin = $true
    } | ConvertTo-Json -Compress
    $response = Invoke-Api -Method 'POST' -Url "$ApiBase/api/login" -Token $null -Body $body
    Assert-Condition ($response.Status -eq 200) '真实 /api/login 状态无效'
    Assert-Condition (
        $response.ContentType -like 'application/json*'
    ) '真实 /api/login MIME 无效'
    $value = $response.Body | ConvertFrom-Json
    Assert-Condition (
        $value.type -eq 'access_token' -and
        $value.access_token -is [string] -and
        $value.access_token.Length -gt 0
    ) '真实 /api/login 未返回内存 token'
    return [string]$value.access_token
}

function Assert-NoSecretInLogs {
    param([Parameter(Mandatory = $true)][string[]]$Secrets)
    $logs = Get-ChildItem -LiteralPath $script:FixtureRoot -Filter '*.log' -File
    foreach ($log in $logs) {
        $content = [System.IO.File]::ReadAllText($log.FullName)
        foreach ($secret in $Secrets) {
            if (-not [string]::IsNullOrEmpty($secret) -and $content.Contains($secret)) {
                throw '子进程日志包含认证秘密'
            }
        }
    }
}

function Read-LatestRequestObservations {
    $files = @(Get-ChildItem `
            -LiteralPath $script:FixtureRoot `
            -Filter 'request-observations-*.json' `
            -File |
            Sort-Object Name)
    Assert-Condition ($files.Count -gt 0) 'fixture 没有产出请求观测'
    $file = $files[-1]
    Assert-PrivateWindowsAcl -Path $file.FullName
    $snapshot = [System.IO.File]::ReadAllText($file.FullName) |
        ConvertFrom-Json
    $snapshotKeys = @($snapshot.PSObject.Properties.Name | Sort-Object)
    Assert-Condition (
        ($snapshotKeys -join "`0") -ceq
        ((@('observations', 'schema', 'sequence') | Sort-Object) -join "`0")
    ) 'fixture 请求观测顶层 schema 漂移'
    $observations = @($snapshot.observations)
    Assert-Condition (
        $snapshot.schema -eq 1 -and
        [int]$snapshot.sequence -eq $observations.Count
    ) 'fixture 请求观测序号无效'
    $expectedKeys = @(
        'has_ab_ver',
        'has_address_book_json',
        'has_bearer',
        'method',
        'path',
        'role',
        'sequence'
    ) | Sort-Object
    for ($index = 0; $index -lt $observations.Count; $index++) {
        $observation = $observations[$index]
        $keys = @($observation.PSObject.Properties.Name | Sort-Object)
        Assert-Condition (
            ($keys -join "`0") -ceq ($expectedKeys -join "`0")
        ) 'fixture 请求观测包含正文、凭证或未知字段'
        Assert-Condition (
            [int]$observation.sequence -eq $index + 1
        ) 'fixture 请求观测顺序无效'
    }
    return $snapshot
}

function Assert-ProductRoleObservations {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][int]$ExpectedProducerSysinfo,
        [Parameter(Mandatory = $true)][int]$ExpectedProducerAddressBook
    )
    $observations = @($Snapshot.observations)
    $productRoles = @($observations | Where-Object {
        $_.role -eq 'service' -or $_.role -eq 'ui-event-producer'
    })
    Assert-Condition (
        $productRoles.Count -eq $observations.Count
    ) 'fixture 请求观测包含产品角色之外的记录'
    $service = @($productRoles | Where-Object { $_.role -eq 'service' })
    $serviceSummary = $service | ConvertTo-Json -Compress
    Assert-Condition (
        $service.Count -eq 1 -and
        $service[0].method -eq 'POST' -and
        $service[0].path -eq '/api/sysinfo' -and
        $service[0].has_bearer -eq $false -and
        $service[0].has_ab_ver -eq $false -and
        $service[0].has_address_book_json -eq $false
    ) "service 请求观测没有证明无凭证 legacy sysinfo：$serviceSummary"
    $unexpectedCredentialed = @($productRoles | Where-Object {
        ($_.has_bearer -eq $true -or $_.has_ab_ver -eq $true) -and
        $_.role -ne 'ui-event-producer'
    })
    Assert-Condition (
        $unexpectedCredentialed.Count -eq 0
    ) 'service 角色携带了 Bearer 或 ab_ver'
    $producerSysinfo = @($productRoles | Where-Object {
        $_.role -eq 'ui-event-producer' -and
        $_.method -eq 'POST' -and
        $_.path -eq '/api/sysinfo'
    })
    $producerAddressBook = @($productRoles | Where-Object {
        $_.role -eq 'ui-event-producer' -and
        $_.method -eq 'GET' -and
        $_.path -eq '/api/ab'
    })
    Assert-Condition (
        $producerSysinfo.Count -eq $ExpectedProducerSysinfo -and
        @($producerSysinfo | Where-Object {
            $_.has_bearer -ne $true -or
            $_.has_ab_ver -ne $true -or
            $_.has_address_book_json -ne $true
        }).Count -eq 0
    ) 'producer 未实证合法与 fallback sysinfo Bearer/ab_ver 路径'
    Assert-Condition (
        $producerAddressBook.Count -eq $ExpectedProducerAddressBook -and
        @($producerAddressBook | Where-Object {
            $_.has_bearer -ne $true -or $_.has_ab_ver -ne $true
        }).Count -eq 0
    ) 'producer 未实证 Bearer /api/ab fallback'
}

$serverRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$clientCandidate = $ClientRepo
if (-not [System.IO.Path]::IsPathRooted($clientCandidate)) {
    $clientCandidate = Join-Path $serverRoot $clientCandidate
}
$clientRoot = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $clientCandidate).Path
)
Assert-Condition (
    [System.IO.File]::Exists((Join-Path $serverRoot 'Cargo.toml'))
) '无法识别 rustdesk-server 仓库'
Assert-Condition (
    [System.IO.File]::Exists((Join-Path $clientRoot 'Cargo.toml')) -and
    [System.IO.File]::Exists((Join-Path $clientRoot 'flutter\pubspec.yaml'))
) '无法识别 RustDesk 客户端仓库'

$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$script:FixtureRoot = Join-Path $temporaryBase (
    'rustdesk-issue9-e2e-' + [Guid]::NewGuid().ToString('N')
)
[void][System.IO.Directory]::CreateDirectory($script:FixtureRoot)
Protect-PrivateDirectory -Path $script:FixtureRoot
Assert-PrivateWindowsAcl -Path $script:FixtureRoot
$productConfigRoot = $null
if ($script:IsWindowsPlatform) {
    $fixtureLeaf = [System.IO.Path]::GetFileName($script:FixtureRoot)
    $configSuffix = $fixtureLeaf.Substring($fixtureLeaf.Length - 16)
    $productAppName = "RustDeskIssue9E2E_$configSuffix"
    $roamingRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ApplicationData
    )
    $productConfigRoot = Join-Path $roamingRoot $productAppName
    Assert-Condition (
        -not [System.IO.Directory]::Exists($productConfigRoot)
    ) '随机产品配置目录发生碰撞'
    [void][System.IO.Directory]::CreateDirectory($productConfigRoot)
    Protect-PrivateDirectory -Path $productConfigRoot
    Assert-PrivateWindowsAcl -Path $productConfigRoot
}

$cargo = (Get-Command cargo -ErrorAction Stop).Source
$flutter = (Get-Command flutter -ErrorAction Stop).Source
$ownerToken = $null
$recipientToken = $null
$emptyToken = $null
$ownerPassword = $null
$recipientPassword = $null
$emptyPassword = $null

try {
    $serverArgs = @(
        'run',
        '--locked',
        '--example',
        'issue9_fixture_server',
        '--',
        "`"$script:FixtureRoot`""
    )
    $script:ServerProcess = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $serverArgs `
        -WorkingDirectory $serverRoot `
        -LogPrefix 'server'

    $readyPath = Join-Path $script:FixtureRoot 'ready.json'
    $credentialsPath = Join-Path $script:FixtureRoot 'credentials.json'
    Wait-PrivateFile -Path $readyPath -Process $script:ServerProcess
    Wait-PrivateFile -Path $credentialsPath -Process $script:ServerProcess
    $ready = [System.IO.File]::ReadAllText($readyPath) | ConvertFrom-Json
    $credentialsRaw = [System.IO.File]::ReadAllText($credentialsPath)
    [System.IO.File]::Delete($credentialsPath)
    $credentials = $credentialsRaw | ConvertFrom-Json
    $credentialsRaw = $null
    Assert-Condition (
        $ready.schema -eq 1 -and
        $ready.api_base -match '^http://127\.0\.0\.1:\d+$'
    ) 'fixture ready schema 或 URL 无效'
    Assert-Condition ($credentials.schema -eq 1) 'fixture credentials schema 无效'
    $apiBase = [string]$ready.api_base
    $ownerPassword = [string]$credentials.owner_password
    $recipientPassword = [string]$credentials.recipient_password
    $emptyPassword = [string]$credentials.empty_password

    $script:HttpClient = New-HttpClient
    $ownerToken = Login-Api `
        -ApiBase $apiBase `
        -Username ([string]$credentials.owner_username) `
        -Password $ownerPassword
    $recipientToken = Login-Api `
        -ApiBase $apiBase `
        -Username ([string]$credentials.recipient_username) `
        -Password $recipientPassword
    $emptyToken = Login-Api `
        -ApiBase $apiBase `
        -Username ([string]$credentials.empty_username) `
        -Password $emptyPassword

    $serviceInputPath = Join-Path $script:FixtureRoot 'service-input.json'
    Write-PrivateJson -Path $serviceInputPath -Value @{
        schema      = 1
        api_base    = $apiBase
        device_id   = [string]$credentials.device_id
        device_uuid = [string]$credentials.device_uuid
    }

    $seedArgs = @(
        'run',
        '--locked',
        '--features',
        'flutter',
        '--example',
        'issue9_process_client',
        '--',
        '--role',
        'seed-legacy',
        '--root',
        "`"$script:FixtureRoot`""
    )
    $seed = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $seedArgs `
        -WorkingDirectory $clientRoot `
        -LogPrefix 'client-seed'
    Wait-SuccessfulExit -Process $seed -Role 'legacy seed'
    Wait-PrivateFile -Path (
        Join-Path $script:FixtureRoot 'legacy-seeded.json'
    ) -Process $null

    $serviceArgs = @(
        'run',
        '--locked',
        '--features',
        'flutter',
        '--example',
        'issue9_process_client',
        '--',
        '--role',
        'service',
        '--root',
        "`"$script:FixtureRoot`""
    )
    $script:ServiceProcess = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $serviceArgs `
        -WorkingDirectory $clientRoot `
        -LogPrefix 'client-service'
    $serviceReadyPath = Join-Path $script:FixtureRoot 'service-ready.json'
    Wait-PrivateFile -Path $serviceReadyPath -Process $script:ServiceProcess
    $serviceReady = [System.IO.File]::ReadAllText($serviceReadyPath) | ConvertFrom-Json
    Assert-Condition (
        $serviceReady.legacy_scrubbed -eq $true -and
        $serviceReady.auth_store_absent -eq $true -and
        $serviceReady.ui_event_absent -eq $true -and
        $serviceReady.no_credential_request_ok -eq $true
    ) 'service 隔离或无凭证请求证明失败'

    $initialFull = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?page=1&page_size=50" `
        -Token $recipientToken `
        -Body $null
    Assert-Condition ($initialFull.Status -eq 200) 'recipient 初始全量状态无效'
    $initialFullJson = $initialFull.Body | ConvertFrom-Json
    Assert-Condition (
        $initialFullJson.mode -eq 'full' -and
        [int64]$initialFullJson.ab_ver -eq 0 -and
        @($initialFullJson.items).Count -eq 0
    ) 'recipient 初始地址簿不是空基线'

    $producerInputPath = Join-Path $script:FixtureRoot 'producer-input.json'
    Write-PrivateJson -Path $producerInputPath -Value @{
        schema             = 1
        api_base           = $apiBase
        owner_username     = [string]$credentials.owner_username
        owner_password     = $ownerPassword
        recipient_username = [string]$credentials.recipient_username
        recipient_password = $recipientPassword
        empty_username     = [string]$credentials.empty_username
        empty_password     = $emptyPassword
        device_id          = [string]$credentials.device_id
        device_uuid        = [string]$credentials.device_uuid
    }
    $producerArgs = @(
        'run',
        '--locked',
        '--features',
        'flutter',
        '--example',
        'issue9_process_client',
        '--',
        '--role',
        'ui-event-producer',
        '--root',
        "`"$script:FixtureRoot`""
    )
    $script:ProducerProcess = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $producerArgs `
        -WorkingDirectory $clientRoot `
        -LogPrefix 'client-producer'
    $producerReadyPath = Join-Path $script:FixtureRoot 'producer-ready.json'
    Wait-PrivateFile -Path $producerReadyPath -Process $script:ProducerProcess
    $producerReady = [System.IO.File]::ReadAllText($producerReadyPath) | ConvertFrom-Json
    Assert-Condition (
        $producerReady.owner_sysinfo_json -eq $true -and
        $producerReady.recipient_fallback -eq $true -and
        $producerReady.cursor_unchanged -eq $true
    ) 'producer 的 sysinfo/fallback/no-ACK 证明失败'
    $initialObservations = Read-LatestRequestObservations
    Assert-ProductRoleObservations `
        -Snapshot $initialObservations `
        -ExpectedProducerSysinfo 2 `
        -ExpectedProducerAddressBook 1

    $encodedDevice = [Uri]::EscapeDataString([string]$credentials.device_id)
    $shareBody = @{
        to_username = [string]$credentials.recipient_username
        permission  = 'view_only'
    } | ConvertTo-Json -Compress
    $share = Invoke-Api `
        -Method 'POST' `
        -Url "$apiBase/api/ab/share/$encodedDevice" `
        -Token $ownerToken `
        -Body $shareBody
    Assert-Condition (
        $share.Status -eq 201 -or $share.Status -eq 200
    ) '创建共享邀请失败'
    $shareJson = $share.Body | ConvertFrom-Json
    Assert-Condition (
        [int64]$shareJson.id -gt 0 -and
        $shareJson.status -eq 'pending' -and
        $shareJson.permission -eq 'view_only'
    ) '共享邀请响应无效'
    $shareId = [int64]$shareJson.id

    $pending = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab/pending?page_size=50" `
        -Token $recipientToken `
        -Body $null
    Assert-Condition ($pending.Status -eq 200) 'pending 拉取失败'
    $pendingJson = $pending.Body | ConvertFrom-Json
    Assert-Condition (
        @($pendingJson.items).Count -eq 1 -and
        [int64]$pendingJson.items[0].id -eq $shareId -and
        $pendingJson.items[0].permission -eq 'view_only'
    ) '邀请未精确出现在 pending'
    $pendingOnlyFull = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?page=1&page_size=50" `
        -Token $recipientToken `
        -Body $null
    $pendingOnlyJson = $pendingOnlyFull.Body | ConvertFrom-Json
    Assert-Condition (
        [int64]$pendingOnlyJson.ab_ver -eq 0 -and
        @($pendingOnlyJson.items).Count -eq 0
    ) 'pending 邀请错误进入 membership/version'

    $accept = Invoke-Api `
        -Method 'POST' `
        -Url "$apiBase/api/ab/accept/$shareId" `
        -Token $recipientToken `
        -Body $null
    Assert-Condition ($accept.Status -eq 200) '接受共享失败'

    $lostFirst = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?ab_ver=0&page_size=50" `
        -Token $recipientToken `
        -Body $null
    $lostRetry = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?ab_ver=0&page_size=50" `
        -Token $recipientToken `
        -Body $null
    Assert-Condition (
        $lostFirst.Status -eq 200 -and
        $lostRetry.Status -eq 200 -and
        $lostFirst.Body -ceq $lostRetry.Body
    ) '响应丢失后的同 cursor 重试不稳定'

    Write-PrivateJson -Path (
        Join-Path $script:FixtureRoot 'accept-go'
    ) -Value @{ schema = 1 }
    Wait-PrivateFile -Path (
        Join-Path $script:FixtureRoot 'accept-event.json'
    ) -Process $script:ProducerProcess

    $flutterInputPath = Join-Path $script:FixtureRoot 'flutter-input.json'
    Write-PrivateJson -Path $flutterInputPath -Value @{
        schema             = 1
        api_base           = $apiBase
        recipient_username = [string]$credentials.recipient_username
        recipient_password = $recipientPassword
    }
    $flutterArgs = @(
        'test',
        'test\models\issue9_address_book_live_contract_test.dart',
        "--dart-define=ISSUE9_FIXTURE_ROOT=$script:FixtureRoot",
        '--reporter',
        'compact'
    )
    $script:FlutterProcess = Start-LoggedProcess `
        -Executable $flutter `
        -Arguments $flutterArgs `
        -WorkingDirectory (Join-Path $clientRoot 'flutter') `
        -LogPrefix 'flutter-live-contract'

    Wait-PrivateFile -Path (
        Join-Path $script:FixtureRoot 'accept-producer-acked.json'
    ) -Process $script:ProducerProcess

    $encodedRecipient = [Uri]::EscapeDataString(
        [string]$credentials.recipient_username
    )
    $cancel = Invoke-Api `
        -Method 'DELETE' `
        -Url "$apiBase/api/ab/share/${encodedDevice}?to_username=$encodedRecipient" `
        -Token $ownerToken `
        -Body $null
    Assert-Condition ($cancel.Status -eq 204) '取消共享失败'
    Write-PrivateJson -Path (
        Join-Path $script:FixtureRoot 'cancel-go'
    ) -Value @{ schema = 1 }

    Wait-PrivateFile -Path (
        Join-Path $script:FixtureRoot 'producer-done.json'
    ) -Process $script:ProducerProcess
    Wait-SuccessfulExit `
        -Process $script:ProducerProcess `
        -Role 'ui-event-producer'
    Wait-SuccessfulExit `
        -Process $script:FlutterProcess `
        -Role 'Flutter live-contract'
    $flutterOutput = [System.IO.File]::ReadAllText(
        (Join-Path $script:FixtureRoot 'flutter-live-contract.stdout.log')
    )
    Assert-Condition (
        $flutterOutput.Contains('All tests passed!')
    ) 'Flutter live-contract 没有报告全部通过'

    $finalFull = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?page=1&page_size=50" `
        -Token $recipientToken `
        -Body $null
    $finalFullJson = $finalFull.Body | ConvertFrom-Json
    Assert-Condition (
        $finalFull.Status -eq 200 -and
        [int64]$finalFullJson.ab_ver -eq 2 -and
        @($finalFullJson.items).Count -eq 0
    ) 'cancel 后全量地址簿未恢复为空'

    $sameVersionBody = @{
        id                = [string]$credentials.device_id
        uuid              = [string]$credentials.device_uuid
        ab_ver            = 2
        address_book_json = $true
    } | ConvertTo-Json -Compress
    $sameVersion = Invoke-Api `
        -Method 'POST' `
        -Url "$apiBase/api/sysinfo" `
        -Token $recipientToken `
        -Body $sameVersionBody
    Assert-Condition (
        $sameVersion.Status -eq 204 -and
        [string]::IsNullOrEmpty($sameVersion.Body)
    ) '相同版本 sysinfo 未返回 204'

    $badToken = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?ab_ver=0&page_size=50" `
        -Token 'issue9-invalid-token' `
        -Body $null
    Assert-Condition ($badToken.Status -eq 401) '坏 token 未返回 401'

    $sentinelBody = @{
        id   = [string]$credentials.device_id
        uuid = [string]$credentials.device_uuid
    } | ConvertTo-Json -Compress
    $sentinel = Invoke-Api `
        -Method 'POST' `
        -Url "$apiBase/api/sysinfo" `
        -Token $null `
        -Body $sentinelBody
    Assert-Condition (
        $sentinel.Status -eq 200 -and
        $sentinel.Body -ceq 'SYSINFO_UPDATED'
    ) 'legacy sysinfo sentinel 契约失败'

    $future = Invoke-Api `
        -Method 'GET' `
        -Url "$apiBase/api/ab?ab_ver=9007199254740991&page_size=50" `
        -Token $emptyToken `
        -Body $null
    Assert-Condition ($future.Status -eq 200) 'future cursor reset 请求失败'
    $futureJson = $future.Body | ConvertFrom-Json
    Assert-Condition (
        $futureJson.mode -eq 'delta' -and
        $futureJson.reset_required -eq $true -and
        [int64]$futureJson.ab_ver -eq 0 -and
        [int64]$futureJson.next_ab_ver -eq 0 -and
        @($futureJson.changes).Count -eq 0
    ) '空服务端 future cursor 未安全 reset 到 0'

    $sysinfoVersion = Invoke-Api `
        -Method 'POST' `
        -Url "$apiBase/api/sysinfo_ver" `
        -Token $null `
        -Body $null
    Assert-Condition (
        $sysinfoVersion.Status -eq 200 -and
        $sysinfoVersion.Body.EndsWith('-pro')
    ) 'sysinfo_ver 未暴露 -pro 能力'

    $inspectArgs = @(
        'run',
        '--locked',
        '--features',
        'flutter',
        '--example',
        'issue9_process_client',
        '--',
        '--role',
        'inspect-state',
        '--root',
        "`"$script:FixtureRoot`""
    )
    $inspectBefore = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $inspectArgs `
        -WorkingDirectory $clientRoot `
        -LogPrefix 'client-state-inspect-before'
    Wait-SuccessfulExit `
        -Process $inspectBefore `
        -Role 'NativeAuthStateV1 inspect before service write'
    $stateInspectionPath = Join-Path $script:FixtureRoot 'state-inspected.json'
    Wait-PrivateFile -Path $stateInspectionPath -Process $null
    $stateBeforeServiceWrite = [System.IO.File]::ReadAllText(
        $stateInspectionPath
    ) | ConvertFrom-Json
    [System.IO.File]::Delete($stateInspectionPath)

    Write-PrivateJson -Path (
        Join-Path $script:FixtureRoot 'service-release'
    ) -Value @{ schema = 1 }
    Wait-PrivateFile -Path (
        Join-Path $script:FixtureRoot 'service-done.json'
    ) -Process $script:ServiceProcess
    Wait-SuccessfulExit -Process $script:ServiceProcess -Role 'service'
    $serviceDone = [System.IO.File]::ReadAllText(
        (Join-Path $script:FixtureRoot 'service-done.json')
    ) | ConvertFrom-Json
    Assert-Condition (
        $serviceDone.legacy_still_empty -eq $true -and
        $serviceDone.unrelated_write_persisted -eq $true
    ) 'service 后写恢复了旧认证镜像'

    $inspectAfter = Start-LoggedProcess `
        -Executable $cargo `
        -Arguments $inspectArgs `
        -WorkingDirectory $clientRoot `
        -LogPrefix 'client-state-inspect-after'
    Wait-SuccessfulExit `
        -Process $inspectAfter `
        -Role 'NativeAuthStateV1 inspect after service write'
    Wait-PrivateFile -Path $stateInspectionPath -Process $null
    $stateAfterServiceWrite = [System.IO.File]::ReadAllText(
        $stateInspectionPath
    ) | ConvertFrom-Json
    foreach ($inspection in @(
            $stateBeforeServiceWrite,
            $stateAfterServiceWrite
        )) {
        Assert-Condition (
            $inspection.schema -eq 1 -and
            $inspection.checksum_valid -eq $true -and
            $inspection.session_absent -eq $true -and
            [int]$inspection.pending_logout_count -eq 0 -and
            $inspection.state_sha256 -match '^[0-9a-f]{64}$'
        ) 'NativeAuthStateV1 重开检查无效'
    }
    Assert-Condition (
        [uint64]$stateAfterServiceWrite.revision -eq
            [uint64]$stateBeforeServiceWrite.revision -and
        [uint64]$stateAfterServiceWrite.auth_epoch -eq
            [uint64]$stateBeforeServiceWrite.auth_epoch -and
        [uint64]$stateAfterServiceWrite.logout_generation -eq
            [uint64]$stateBeforeServiceWrite.logout_generation -and
        $stateAfterServiceWrite.state_sha256 -ceq
            $stateBeforeServiceWrite.state_sha256
    ) 'service barrier 后写改变了 producer 权威 revision/cursor/pending'
    $finalObservations = Read-LatestRequestObservations
    Assert-ProductRoleObservations `
        -Snapshot $finalObservations `
        -ExpectedProducerSysinfo 4 `
        -ExpectedProducerAddressBook 4
    Assert-Condition (
        @($finalObservations.observations | Where-Object {
            $_.role -eq 'service'
        }).Count -eq 1
    ) 'service barrier 后产生了额外 HTTP 请求'

    foreach ($forbiddenFile in @(
            'credentials.json',
            'service-input.json',
            'producer-input.json',
            'flutter-input.json',
            'accept-event.json',
            'cancel-event.json',
            'accept-ack.json',
            'cancel-ack.json'
        )) {
        Assert-Condition (
            -not [System.IO.File]::Exists(
                (Join-Path $script:FixtureRoot $forbiddenFile)
            )
        ) "一次性私有文件未删除：$forbiddenFile"
    }

    $secrets = @(
        $ownerPassword,
        $recipientPassword,
        $emptyPassword,
        $ownerToken,
        $recipientToken,
        $emptyToken,
        'issue9-legacy-secret-must-be-scrubbed'
    )
    $logSecrets = @(
        $secrets
        [string]$credentials.owner_username
        [string]$credentials.recipient_username
        [string]$credentials.empty_username
    )
    $serverStopPath = Join-Path $script:FixtureRoot 'stop'
    Write-PrivateJson -Path $serverStopPath -Value @{ schema = 1 }
    Wait-SuccessfulExit `
        -Process $script:ServerProcess `
        -Role 'Issue #9 fixture server'
    Assert-NoSecretInLogs -Secrets $logSecrets
    if ($null -ne $productConfigRoot) {
        foreach ($configFile in Get-ChildItem `
                -LiteralPath $productConfigRoot `
                -File `
                -Recurse) {
            $configText = [System.IO.File]::ReadAllText($configFile.FullName)
            foreach ($secret in $secrets) {
                if (-not [string]::IsNullOrEmpty($secret)) {
                    Assert-Condition (
                        -not $configText.Contains($secret)
                    ) 'service 清理后的产品配置仍含认证秘密'
                }
            }
            Assert-PrivateWindowsAcl -Path $configFile.FullName
        }
    }
    $stateFiles = Get-ChildItem `
        -LiteralPath (Join-Path $script:FixtureRoot 'client-auth') `
        -Filter 'state.json' `
        -File `
        -Recurse
    Assert-Condition (@($stateFiles).Count -eq 1) 'NativeAuthStateV1 state.json 数量无效'
    $stateFile = @($stateFiles)[0]
    $stateText = [System.IO.File]::ReadAllText($stateFile.FullName)
    foreach ($secret in $secrets) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            Assert-Condition (
                -not $stateText.Contains($secret)
            ) '清理后的 NativeAuthStateV1 仍含认证秘密'
        }
    }
    Assert-PrivateWindowsAcl -Path $stateFile.FullName

    Write-Output (
        'Issue #9 跨仓 E2E 通过：service 隔离、真实登录、sysinfo/fallback、' +
        'accept/cancel Flutter 双段观察与 ACK、204/401/sentinel/reset/重试均已验证。'
    )
}
finally {
    if ($null -ne $script:HttpClient) {
        $script:HttpClient.Dispose()
    }
    if ($null -ne $script:FixtureRoot -and
        [System.IO.Directory]::Exists($script:FixtureRoot)) {
        $stopPath = Join-Path $script:FixtureRoot 'stop'
        if (-not [System.IO.File]::Exists($stopPath)) {
            try {
                Write-PrivateJson -Path $stopPath -Value @{ schema = 1 }
            }
            catch {
                # 后续仍会按已跟踪 PID 收尾。
            }
        }
    }
    if ($null -ne $script:ServerProcess) {
        try {
            if (-not $script:ServerProcess.WaitForExit(10000)) {
                Stop-TrackedProcess -Process $script:ServerProcess
            }
        }
        catch {
            Stop-TrackedProcess -Process $script:ServerProcess
        }
    }
    Stop-TrackedProcess -Process $script:FlutterProcess
    Stop-TrackedProcess -Process $script:ProducerProcess
    Stop-TrackedProcess -Process $script:ServiceProcess

    if ($null -ne $productConfigRoot -and
        [System.IO.Directory]::Exists($productConfigRoot)) {
        $resolvedProductConfig = [System.IO.Path]::GetFullPath($productConfigRoot)
        $roamingRootForCleanup = [System.IO.Path]::GetFullPath(
            [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::ApplicationData
            )
        )
        $productLeafForCleanup = [System.IO.Path]::GetFileName(
            $resolvedProductConfig
        )
        if ([System.IO.Path]::GetDirectoryName($resolvedProductConfig) -ne
                $roamingRootForCleanup -or
            -not $productLeafForCleanup.StartsWith(
                'RustDeskIssue9E2E_',
                [System.StringComparison]::Ordinal
            )) {
            throw '拒绝删除未通过范围校验的产品配置目录'
        }
        [System.IO.Directory]::Delete($resolvedProductConfig, $true)
    }

    if ($null -ne $script:FixtureRoot -and
        [System.IO.Directory]::Exists($script:FixtureRoot)) {
        $resolvedFixture = [System.IO.Path]::GetFullPath($script:FixtureRoot)
        $expectedPrefix = [System.IO.Path]::GetFullPath(
            (Join-Path $temporaryBase 'rustdesk-issue9-e2e-')
        )
        if (-not $resolvedFixture.StartsWith(
                $expectedPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw '拒绝删除未通过范围校验的 fixture 目录'
        }
        [System.IO.Directory]::Delete($resolvedFixture, $true)
    }
}
