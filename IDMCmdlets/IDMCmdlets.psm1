# Load cmdlets from module subfolder
$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Path

Resolve-Path "$ModuleRoot\Cmdlets\*.ps1" | ForEach-Object -Process {
. $_.ProviderPath
}
