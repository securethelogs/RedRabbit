# Get-Process | select @{Name='Name'; Expression={$_.MainModule.FileVersionInfo.FileDescription}}
Get-Process | select @{Name='Name'; Expression={$_.MainModule.FileVersionInfo.FileDescription}} |? Name -match 'power'
joder
