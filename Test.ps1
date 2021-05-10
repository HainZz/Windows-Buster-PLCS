New-Item -Path . -Name "Results.txt" -ItemType "file" 
systeminfo | Set-Content -Path .\Results.txt 
Add-Content -Path .\Results.txt -Value "`n" 
systeminfo | Set-Content -Path .\SystemInfo.txt 
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"| Out-File -FilePath .\Results.txt -Append 
wmic qfe get Caption,Description,HotFixID,InstalledOn| Out-File -FilePath .\Results.txt -Append 
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%| Out-File -FilePath .\Results.txt -Append 
