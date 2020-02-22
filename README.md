# RedRabbit

![psbrutezip](https://ctrla1tdel.files.wordpress.com/2020/02/redrabbit.jpg)

RedRabbit is a PowerShell script aimed at helping pentesters conduct ethical hacking #RedTeam

<b> To Run: </b>

You can either run locally by downloading the script or run remotely using: 

powershell –nop –c “iex(New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/securethelogs/RedRabbit/master/redrabbit.ps1’)”


<b> Help </b>

Option 1: Quick Recon <br>
-	Lists User
-	Lists Host
-	Lists Network Interfaces
-	Lists User Groups (inc domain)
-	Shows Privilege
-	Lists Local Admins
-	Lists Local Users
-	Lists Current Logged in Users
-	Shows Installed Programs
-	Tests If Internet Is Reachable
-	Shows Local Firewall Rules 

Option 2: Scan Subnet <br>
This option will find the current subnet in which the machine is connected to and perform the following: 
-	Scan for Live Hosts
-	Resolve DNS for Live Hosts
-	Scan for Open Ports on Live Hosts

Option 3: Clipboard Logger <br>
This is my PSClippy scripts which creates a PowerShell session in the background. This session will record, and values copied to clipboard and store them. Once a threshold of 10 is met, it will either store to file or upload to PasteBin. 

Option 4: Network Scanner <br>
This is a simple network scanner which will allow you to either scan:
-	Common Ports
-	Full Scan (Ports 1-65535)
-	Quick Scan (Ports 1-65535 but less wait time as above option)

 Option 5: DNS Resolver <br>
 This will allow you to resolve an IP to either a single IP address or multiple, using a txt file. 

Option 6: Brute Force ZIP <br>
This option will allow you to brute force a ZIP file using a wordlist.

Option 7: Brute WinRM <br>
This option will scan and allow you to brute force credentials using the WinRM service. For this to work, you need:
-	A machine running the WinRM service (Port open)
-	A user list
-	A password list

Option 8: Test Extraction Connection <br>
Given your method of choice, this will test if the machine can reach your destination on common ports (80,443,445).

Option 9: Show Local Firewall Deny Rules <br>
This option will display the local firewall rules which have a deny action and format them in a handy table. 
<br>
OSINT Options
<br>
Option A: Find Subdomains <br>
This option will allow you to search the internet for subdomains. 

Option B: Daily PasteBin <br>
This option will pull the recent pastes and search them for key words. The script will then display each and highlight any juicy values such as passwords or API keys. 

Option C: Scan Azure Resource <br>
This option will allow you to hunt for reachable Azure resource based on a wordlist provided.

Option D: Scan Socials for Usernames <br>
This will scan a few social media sites for a matching username. 


