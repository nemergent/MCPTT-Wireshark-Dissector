$executingScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

$destdir="$env:APPDATA\Wireshark\plugins\"
New-Item -Force -ItemType directory -Path $destdir
Copy-Item -path $executingScriptDirectory\* -Include "*.lua" -Destination $destdir