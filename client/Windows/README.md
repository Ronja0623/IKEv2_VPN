# Windows Setup Guidance

## Setup Steps
1. Download CA
1. Open `Powershell` as Administrator
1. `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -CAPath <path to CA> -ServerIP <IP of the VPN> -VPNName <name>`  
   `-ExecutionPolicy Bypass` only applies to this one run, so your execution policy setting is left unchanged.