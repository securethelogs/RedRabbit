# RedRabbit

![RedRabbit](https://ctrla1tdel.files.wordpress.com/2020/03/v3.gif)

## About

RedRabbit is a PowerShell script aimed at helping pentesters conduct ethical hacking #RedTeam. 
The aim is to highlight just how Powerful PowerShell is and how it can be used against you (Ethically).

## To Run

You can either run locally by downloading the script or run remotely using: 

powershell –nop –c “iex(New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/securethelogs/RedRabbit/master/redrabbit.ps1’)”

<b>If you run remotely, you will always get the latest version</b>

## Help

Option info and help can be found here: https://securethelogs.com/redrabbit-ps1/

## Recent Update

- RedRabbit now checks for admin session and tries to query AD to check if Domain Admin.
- Password extraction (SAM/SYSTEM File, Credential Manager and Wireless Profiles)
- Encode Commands
- Run Encoded Commands

- Azure Feature has now been added! 

![preview](https://ctrla1tdel.files.wordpress.com/2020/03/azure.gif)
