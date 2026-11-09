# Adds the install directory to the machine PATH or removes it, keeping the
# value REG_EXPAND_SZ so entries such as %SystemRoot% stay unexpanded.
param(
    [Parameter(Mandatory = $true)][ValidateSet('add', 'remove')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Dir
)
$ErrorActionPreference = 'Stop'

$key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$current = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
$target = $Dir.TrimEnd('\')

$parts = @($current -split ';' | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ine $target })
if ($Action -eq 'add') {
    $parts += $target
}

Set-ItemProperty -Path $key.PSPath -Name 'Path' -Value ($parts -join ';') -Type ExpandString
