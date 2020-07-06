# RedRabbit

![RedRabbit](https://ctrla1tdel.files.wordpress.com/2020/05/redrabbitv5.gif)

## About

RedRabbit is a PowerShell script aimed at helping pentesters conduct ethical hacking #RedTeam. 
The aim is to highlight just how Powerful PowerShell is and how it can be used against you (Ethically).

## To Run

You can either run locally by downloading the script or run remotely using: 

powershell –nop –c “iex(New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/securethelogs/RedRabbit/master/redrabbit.ps1’)”

<b>If you run remotely, you will always get the latest version</b>

## Help

Option info and help can be found here: https://securethelogs.com/redrabbit-ps1/

YouTube: https://youtu.be/9kXi2aqfb2M


## Recent Update

Fixed:

- Loop issue with BruteForce Zip
- Performance for "Quick recon"

Feature Update v5:

- Quick Recon - Shows Local FW Blocks only to increase speed
- Reverse Shell - Netcat shell
- Flood - Create a session that generates mass logs whilst you "work" (Masking)
- PassVol - https://github.com/securethelogs/PassVol
- KeyLogger - https://github.com/securethelogs/keylogger

