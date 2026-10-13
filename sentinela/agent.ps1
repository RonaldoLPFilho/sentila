# Agente executado DENTRO do Windows Sandbox. Também aceita rodar no host em modo de teste (NoShutdown + SnapRoots restritos).
param([Parameter(Mandatory = $true)][string]$Params)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$cfg = Get-Content -LiteralPath $Params -Raw -Encoding UTF8 | ConvertFrom-Json
$Out = $cfg.OutDir
$Seconds = [int]$cfg.Seconds
$utf8 = New-Object Text.UTF8Encoding $false

function Progress([string]$m) { try { [IO.File]::WriteAllText((Join-Path $Out 'progress.txt'), $m, $utf8) } catch {} }

function Get-FileSnap($roots) {
    $h = @{}
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        $depth = if ($r -like '*Program Files*') { 3 } else { 40 }
        Get-ChildItem -LiteralPath $r -Recurse -Depth $depth -Force -File -ErrorAction SilentlyContinue |
            ForEach-Object { $h[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }
    }
    return $h
}

function Get-Persist {
    $o = @{}
    $keys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
    foreach ($k in $keys) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($item) { $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $o["run|$k|$($_.Name)"] = [string]$_.Value } }
    }
    # Assinaturas permanentes de WMI e sequestro de COM (persistência sem arquivo em pasta de inicialização)
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { $o["run|WMI|$($_.Filter.Name)"] = [string]$_.Consumer }
    Get-CimInstance Win32_Service | ForEach-Object { $o["svc|$($_.Name)"] = [string]$_.PathName }
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $o["task|$($_.TaskPath)$($_.TaskName)"] = '1' }
    $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { $o["ifeo|$($_.PSChildName)"] = [string]$d }
    }
    return $o
}

function Get-Uninstall {
    $l = @{}
    foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
        Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { $n = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName; if ($n) { $l[$_.PSChildName] = [string]$n } }
    }
    return $l
}

function Get-Dns { try { @(Get-DnsClientCache | ForEach-Object { $_.Entry }) } catch { @() } }
function Get-HostsHash { try { (Get-FileHash "$env:windir\System32\drivers\etc\hosts" -Algorithm SHA256).Hash } catch { '' } }

$report = [ordered]@{ ok = $true; error = $null; target = $cfg.Target; kind = $cfg.Kind; seconds = $Seconds; start_error = $null }
try {
    Progress 'boot'
    Start-Sleep -Seconds 3

    # Cópia local gravável da amostra (a pasta compartilhada é somente leitura)
    $sampleLocal = Join-Path $cfg.WorkDir 'Sample'
    New-Item -ItemType Directory -Force -Path $sampleLocal | Out-Null
    Copy-Item -Path (Join-Path $cfg.SampleDir '*') -Destination $sampleLocal -Recurse -Force

    # Arquivos-isca para detectar ransomware
    New-Item -ItemType Directory -Force -Path $cfg.DecoyDir | Out-Null
    # Tamanhos e extensões variados: ransomware costuma ignorar arquivos pequenos ou de certas extensões
    $decoys = @{}
    $exts = 'txt', 'docx', 'xlsx', 'jpg', 'pdf', 'png', 'csv', 'pptx', 'sql', 'zip', 'mp3', 'db'
    $sizes = 700, 3000, 20000, 90000, 250000, 1200, 40000, 600000, 5000, 150000, 15000, 70000
    $rng = New-Object Random 4242
    foreach ($i in 1..12) {
        $p = Join-Path $cfg.DecoyDir ("documento_{0}.{1}" -f $i, $exts[$i - 1])
        $bytes = New-Object byte[] $sizes[$i - 1]
        $rng.NextBytes($bytes)
        [IO.File]::WriteAllBytes($p, $bytes)
        $decoys[$p] = (Get-FileHash $p -Algorithm SHA256).Hash
    }

    Progress 'snapshot'
    $beforeFiles = Get-FileSnap $cfg.SnapRoots
    $beforePersist = Get-Persist
    $beforeUninst = Get-Uninstall
    $beforeDns = Get-Dns
    $beforeHosts = Get-HostsHash
    $mp0 = Get-MpPreference -ErrorAction SilentlyContinue
    $beforeRealtimeOff = [bool]$mp0.DisableRealtimeMonitoring   # só conta como adulteração se MUDOU durante a execução
    $beforeExcl = @(@($mp0.ExclusionPath) + @($mp0.ExclusionExtension) + @($mp0.ExclusionProcess) | Where-Object { $_ -and $_ -notlike 'N/A*' })
    $beforeProcs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $beforeProcs[[int]$_.ProcessId] = $true }
    $startTime = Get-Date

    # Executa a amostra
    Progress 'run|0'
    $full = Join-Path $sampleLocal $cfg.Target
    $dir = Split-Path $full
    $proc = $null
    try {
        switch ($cfg.Kind) {
            'msi' { $proc = Start-Process msiexec.exe -ArgumentList '/i', "`"$full`"", '/qn', '/norestart' -PassThru -ErrorAction Stop }
            'dll' { $proc = Start-Process rundll32.exe -ArgumentList "`"$full`",Sentinela" -WorkingDirectory $dir -PassThru -ErrorAction Stop }
            'bat' { $proc = Start-Process cmd.exe -ArgumentList '/c', "`"$full`"" -WorkingDirectory $dir -PassThru -ErrorAction Stop }
            'ps1' { $proc = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$full`"" -WorkingDirectory $dir -PassThru -ErrorAction Stop }
            'wsh' { $proc = Start-Process wscript.exe -ArgumentList '//Nologo', "`"$full`"" -WorkingDirectory $dir -PassThru -ErrorAction Stop }
            'hta' { $proc = Start-Process mshta.exe -ArgumentList "`"$full`"" -WorkingDirectory $dir -PassThru -ErrorAction Stop }
            default { $proc = Start-Process -FilePath $full -WorkingDirectory $dir -PassThru -ErrorAction Stop }
        }
    }
    catch { $report.start_error = $_.Exception.Message }

    $samplePid = if ($proc) { $proc.Id } else { -1 }
    $own = $PID
    $noise = 'wmiprvse.exe', 'conhost.exe', 'backgroundtaskhost.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe', 'smartscreen.exe', 'taskhostw.exe', 'runtimebroker.exe', 'dllhost.exe', 'werfault.exe', 'msmpeng.exe', 'mpcmdrun.exe'
    $seen = @{}; $parent = @{}; $newProcs = New-Object Collections.ArrayList
    $cpu = @{}; $conns = @{}
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $cores = [Math]::Max(1, [int]$env:NUMBER_OF_PROCESSORS)

    function Test-Descends([int]$procId) {
        $cur = $procId
        for ($i = 0; $i -lt 12 -and $parent.ContainsKey($cur); $i++) { if ($cur -eq $samplePid) { return $true }; $cur = $parent[$cur] }
        return ($cur -eq $samplePid)
    }

    function Add-Proc([int]$id, [string]$nm, [int]$ppidHint) {
        if ($noise -contains $nm.ToLower()) { return }
        $ci = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
        $cmdline = [string]$ci.CommandLine
        $ppid = if ($ci) { [int]$ci.ParentProcessId } else { $ppidHint }
        $parent[$id] = $ppid
        [void]$newProcs.Add([ordered]@{ pid = $id; ppid = $ppid; name = $(if ($ci) { [string]$ci.Name } else { $nm }); path = [string]$ci.ExecutablePath;
                cmd = $cmdline.Substring(0, [Math]::Min(400, $cmdline.Length)); descends = (Test-Descends $id); t = [int]$sw.Elapsed.TotalSeconds })
    }

    # Eventos de início de processo (pegam até processos de milissegundos; exige administrador, como no sandbox)
    $evtOk = $false
    try { Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier 'SentProc' -ErrorAction Stop | Out-Null; $evtOk = $true } catch {}

    $tick = 0
    while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
        if ($evtOk) {
            foreach ($ev in @(Get-Event -SourceIdentifier 'SentProc' -ErrorAction SilentlyContinue)) {
                $n = $ev.SourceEventArgs.NewEvent
                Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
                $id = [int]$n.ProcessID
                if ($beforeProcs.ContainsKey($id) -or $seen.ContainsKey($id) -or $id -eq $own) { continue }
                $seen[$id] = $true
                Add-Proc $id ([string]$n.ProcessName) ([int]$n.ParentProcessID)
            }
        }
        # Sondagem (~150 ms): complementa os eventos e é a única fonte quando não há privilégio de administrador
        foreach ($gp in [Diagnostics.Process]::GetProcesses()) {
            $id = [int]$gp.Id
            if ($beforeProcs.ContainsKey($id) -or $seen.ContainsKey($id) -or $id -eq $own) { continue }
            $seen[$id] = $true
            Add-Proc $id ([string]$gp.ProcessName + '.exe') 0
        }
        if ($tick % 6 -eq 0) {
            Progress ('run|' + [int]$sw.Elapsed.TotalSeconds)
            foreach ($e in $newProcs) {
                if ($e.descends) { $gp = Get-Process -Id $e.pid -ErrorAction SilentlyContinue; if ($gp) { $cpu[$e.pid] = $gp.TotalProcessorTime.TotalSeconds } }
            }
            # Só conexões de processos criados depois do início (ignora o ruído do próprio Windows)
            Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::1?$|::)' -and -not $beforeProcs.ContainsKey([int]$_.OwningProcess) } | ForEach-Object {
                $k = "$($_.RemoteAddress):$($_.RemotePort)"
                if (-not $conns.ContainsKey($k)) { $conns[$k] = [ordered]@{ pid = $_.OwningProcess; proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; remote = $_.RemoteAddress; port = $_.RemotePort } }
            }
        }
        $tick++
        Start-Sleep -Milliseconds 150
    }
    $elapsed = [Math]::Max(1, $sw.Elapsed.TotalSeconds)
    if ($evtOk) { Unregister-Event -SourceIdentifier 'SentProc' -ErrorAction SilentlyContinue }

    Progress 'collect'
    # Estado final da amostra e janelas visíveis
    $report.sample_exited = $false; $report.exit_code = $null
    if ($proc) { $proc.Refresh(); $report.sample_exited = [bool]$proc.HasExited; if ($proc.HasExited) { $report.exit_code = $proc.ExitCode } }
    $titles = @(Get-Process | Where-Object { $_.MainWindowTitle -and $_.Id -ne $own } | ForEach-Object { $_.MainWindowTitle } | Select-Object -First 8)
    try {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object Drawing.Bitmap $b.Width, $b.Height
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location, [Drawing.Point]::Empty, $b.Size)
        $bmp.Save((Join-Path $Out 'screenshot.png'), [Drawing.Imaging.ImageFormat]::Png)
    }
    catch {}

    Start-Sleep -Seconds 4   # dá tempo ao Defender de reagir

    # Diferenças de arquivos
    $afterFiles = Get-FileSnap $cfg.SnapRoots
    # Ignora só o ruído conhecido do próprio Windows (padrões estreitos: nada de pastas inteiras onde um malware poderia se esconder)
    $ignore = '\\Microsoft\\Windows Defender|\\Windows\\WER\\|\\AppData\\Local\\Packages\\|\\ProgramData\\Microsoft\\(Windows\\(WER|Caches|AppRepository|SystemData|DeviceMetadataCache)|Diagnosis|Search|Network|Crypto|Event Viewer)|\\Microsoft\\Edge|\\Microsoft\\Windows\\(Caches|Explorer|INetCache|History|WebCache|Recent|Notifications|PowerShell|SettingsBackup|Themes)|NTUSER|\\AppData\\Local\\Temp\\(Low|WER|chrome|edge)'
    $newFiles = New-Object Collections.ArrayList
    foreach ($k in $afterFiles.Keys) {
        if ($k -match $ignore) { continue }
        if (-not $beforeFiles.ContainsKey($k) -or $beforeFiles[$k] -ne $afterFiles[$k]) { [void]$newFiles.Add($k) }
    }
    $nfOut = @($newFiles | Select-Object -First 300 | ForEach-Object { [ordered]@{ path = $_; size = [int64]($afterFiles[$_] -split '\|')[0] } })

    # Persistência
    $afterPersist = Get-Persist
    $runKeys = @(); $svcs = @(); $tasks = @(); $ifeo = @()
    foreach ($k in $afterPersist.Keys) {
        if ($beforePersist.ContainsKey($k) -and $beforePersist[$k] -eq $afterPersist[$k]) { continue }
        $v = $afterPersist[$k]
        switch -Wildcard ($k) {
            'run|*' { $runKeys += (($k -split '\|')[2] + ' = ' + $v) }
            'svc|*' { $svcs += (($k -split '\|')[1] + ' = ' + $v) }
            'task|*' { $tasks += ($k -replace '^task\|', '') }
            'ifeo|*' { $ifeo += (($k -split '\|')[1] + ' -> ' + $v) }
        }
    }
    $afterUninst = Get-Uninstall
    $installed = @($afterUninst.Keys | Where-Object { -not $beforeUninst.ContainsKey($_) } | ForEach-Object { $afterUninst[$_] })

    # Defender
    $threats = @()
    try {
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt $startTime.AddSeconds(-2) } | ForEach-Object {
            $nm = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
            $threats += [ordered]@{ name = [string]$nm; resources = [string]($_.Resources -join ';') }
        }
    }
    catch {}
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    $excl = @(@($mp.ExclusionPath) + @($mp.ExclusionExtension) + @($mp.ExclusionProcess) | Where-Object { $_ -and $_ -notlike 'N/A*' -and $beforeExcl -notcontains $_ })

    # Arquivos-isca
    $tampered = 0
    foreach ($p in $decoys.Keys) {
        if (-not (Test-Path -LiteralPath $p)) { $tampered++; continue }
        if ((Get-FileHash $p -Algorithm SHA256).Hash -ne $decoys[$p]) { $tampered++ }
    }

    $cpuTotal = ($cpu.Values | Measure-Object -Sum).Sum
    $report.new_processes = @($newProcs)
    $report.connections = @($conns.Values)
    $report.dns = @(Get-Dns | Where-Object { $beforeDns -notcontains $_ } | Select-Object -First 20)
    $report.new_files = $nfOut
    $report.new_files_total = $newFiles.Count
    $report.persistence = [ordered]@{ run_keys = $runKeys; services = $svcs; tasks = $tasks; ifeo = $ifeo }
    $report.installed = $installed
    $mps = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $report.defender = [ordered]@{ threats = $threats; active = [bool]($mps.RealTimeProtectionEnabled -and $mps.AntivirusEnabled)
        realtime_disabled = ([bool]$mp.DisableRealtimeMonitoring -and -not $beforeRealtimeOff); exclusions_added = @($excl) }
    $report.hosts_changed = ((Get-HostsHash) -ne $beforeHosts)
    $report.decoys_total = $decoys.Count
    $report.decoys_tampered = $tampered
    $report.cpu_percent = [Math]::Round(100 * $cpuTotal / $elapsed / $cores, 1)
    $report.windows = $titles
}
catch {
    $report.ok = $false
    $report.error = $_.Exception.Message
}

$reportName = if ($cfg.ReportName) { [string]$cfg.ReportName } else { 'report.json' }
$doneName = if ($cfg.DoneName) { [string]$cfg.DoneName } else { 'done.flag' }
try { [IO.File]::WriteAllText((Join-Path $Out $reportName), ($report | ConvertTo-Json -Depth 7 -Compress), $utf8) }
catch { Progress 'error|report-write' }
Progress 'done'
New-Item -ItemType File -Force -Path (Join-Path $Out $doneName) | Out-Null
if (-not $cfg.NoShutdown) { Start-Sleep -Seconds 2; shutdown.exe /s /t 0 /f }
