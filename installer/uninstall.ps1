# Desinstalador do Sentinela. Fica na pasta de instalação e é chamado pelo atalho / "Aplicativos instalados".
param([switch]$Silent, [switch]$RemoveSettings)
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
# Trava de segurança: só apaga se for mesmo uma instalação do Sentinela
if (-not (Test-Path -LiteralPath (Join-Path $dir 'Sentinela.exe')) -or ((Split-Path $dir -Leaf) -ne 'Sentinela')) {
    if (-not $Silent) { [Windows.Forms.MessageBox]::Show("Esta pasta não parece ser uma instalação do Sentinela:`n$dir", 'Sentinela', 'OK', 'Warning') | Out-Null }
    exit 1
}

if (-not $Silent) {
    $r = [Windows.Forms.MessageBox]::Show('Deseja desinstalar o Sentinela?', 'Sentinela', 'YesNo', 'Question')
    if ($r -ne 'Yes') { exit 0 }
    $rm = [Windows.Forms.MessageBox]::Show("Remover também as configurações (inclui a chave do VirusTotal salva)?", 'Sentinela', 'YesNo', 'Question')
    if ($rm -eq 'Yes') { $RemoveSettings = $true }
}

Stop-Process -Name 'Sentinela' -Force
Start-Sleep -Milliseconds 600

# Atalhos
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Sentinela.lnk') -Force
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'Sentinela') -Recurse -Force

# Registro (somente o que o instalador criou)
Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\Sentinela' -Recurse -Force
Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela' -Recurse -Force

if ($RemoveSettings) { Remove-Item -LiteralPath (Join-Path $env:APPDATA 'Sentinela') -Recurse -Force }

# A pasta contém este script: apaga logo depois que ele terminar
Set-Location $env:TEMP
Start-Process cmd.exe -ArgumentList '/c', "ping 127.0.0.1 -n 3 >nul & rmdir /s /q `"$dir`"" -WindowStyle Hidden
if (-not $Silent) { [Windows.Forms.MessageBox]::Show('Sentinela desinstalado.', 'Sentinela', 'OK', 'Information') | Out-Null }
