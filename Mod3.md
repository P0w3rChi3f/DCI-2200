# Module 3 Survey State Operations  

## Exercise 3.1-01 Document Network Segments  Subnets and Topology Based on Network Maps

* [NMap CheatSheet](https://highon.coffee/blog/nmap-cheat-sheet/)  
* Private Address Ranges
  * Class A: 10.0.0.0 to 10.255.255.255.
  * Class B: 172.16.0.0 to 172.31.255.255.
  * Class C: 192.168.0.0 to 192.168.255.255.

## Exercise 3.1-02: Determine Traffic Routes Based on Network Topology Maps

## Exercise 3.1-03 Develop Sensor Strategy - Placement of Sensors  

* [Basic Network Devies Logging](https://www.networkcomputing.com/networking/network-device-management-part-1-snmp-logging)  
* [Learn about NetFlow from Cisco Documentation](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html)  
* [Network Traffic Logging](https://sansorg.egnyte.com/dl/v8yKo67ANC)  
* [IDS and IPS Deployment Strategies](https://www.sans.org/white-papers/2143/)  
* Network map for path analysis notes
  * Hub and Switch does not have IP addresses or Macs listed
  * Switch does switching based on MAC, so MAC does not change.  

## Exercise 3.1-04: Develop Sensor Strategy - Place New Sensors and Reuse Local Resources  

[Network Map](images\Mod3\E3-1-04\NetWorkMap-S1-S2.png)

* Scenario 1
  * Q1 - Tapping any router will cause a network outage, so this cannot be done per the supported commander.  Using the IDS to do capture full PCAP is a better choice.  It is already in the network and detecting things already.  The risk of using the IDS is that it may be compromised already.

    ```notes  
        Tapping any router will cause a network outage, so this cannot be done per the supported commander.  Using the IDS to do capture full PCAP is a better choice.  It is already in the network and detecting things already.  The risk of using the IDS is that it may be compromised already.
    ```  

  * Q2 - This will allow us to see the attacker has already established C2.  If they have, it will give us information as to what is being sent and received from the attackers and victims.

    ```notes
        This will allow us to see the attacker has already established C2.  If they have, it will give us information as to what is being sent and received from the attackers and victims.
    ```

  * Q3 - Yes, that will cause an outage for any packets leaving or entering the network.  

  ```notes
     Yes, that will cause an outage for any packets leaving or entering the network.
  ```

  * Q4 - Depends if we can connect anything to the span.  From our current inventory, it doesn't appear we do.  If the local organization had an extra Linux machine hanging around, we could use it or if the IPS was close enough and had another NIC, we could send the traffic there.  

  ```notes
    Depends if we can connect anything to the span.  From our current inventory, it doesn't appear we do.  If the local organization had an extra Linux machine hanging around, we could use it or if the IPS was close enough and had another NIC, we could send the traffic there.
  ```

  * Q5 - If we had anything to connect to the span.  We would get all the traffic entering and leaving the base Servers subnet  

  ```notes
    If we had anything to connect to the span.  We would get all the traffic entering and leaving the base Servers subnet
  ```

  * Q6 - Private Hawker wants to use and configure the HBSS on the .3 host machine (local defender???s software) in order to monitor for threat activity. Why would it be important to use organic capabilities before we use our own?  

  ```notes
    Once configured, we can leave documentation with the customer on how to configure and monitor their own equipment.  If we used ours, we would not have anything to leave behind for the customer to use and defend with.
  ```

  * Q7 - Private Hawker wants to know why she has to monitor the network and make observations instead of immediately removing the malware from the host machine. Why is it important to monitor the network and make observations before containing and eradicating the malicious actor???s activity?  

  ```notes
    Many things to think about here.  We already know the malware is on one machine, what we don't know is how many machines have this malware.  By monitoring the malware and its traffic, we can determine who it is talking to, possibly find out how widespread this thing is.  We can also gain some knowledge of TTP's that we could report up.
  ```

* Scenario 2  
  * Q1 - Private Hawker doesn't have any experience in a live network intrusion. Based on the information previously given, provide a sensor strategy describing the best location to place new sensors and which local resources will be re-purposed/configured.

    Develop a sensor strategy describing the best location to place new sensors and which local resources will be re-purposed/configured in the space below. Your sensor strategy can be written below in any template or format you want. Pay special attention to the impact of your decisions. Thoroughly explain why you are making these changes in the sensor strategy.

  ```notes
    For starters, we have a 2-hour window where we can take down the network.  I would try to convert the IDS to an IPS/IDS and move it inline between the firewall and .10 switch if it could handle the throughput. Based on the intel dump, I would say we are getting 2 new senors.  I would place one on a span port connected to 10.57.0.3 and the other one at 10.57.5.2.
  ```  

* Scenario 3 - [Critical Asset Map](images\Mod3\E3-1-04\CriticalAssetMap.pdf)  
  * Q1 - Using the map and based on the COA 1 in the attack diagram provided by the CTE squad, what is the best sensor placement position, if your team only has two network sensors? Why?

  ```notes
    I would place one on a span port on 10.0.1.4 and 10.6.0.2.  Both of those locations will give me visibility of the critical systems.
  ```

  * Q2 - Using the same resources, what is the best sensor placement position if your team only has one network sensor? Why?  

  ```notes
    If you have the port density, I would place it at the firewall and span one of its ports.  If that is not a possibility, it would be a span off of 10.0.1.4.  Both places get me closer to the egress point to monitor for data exfil.
  ```

  * Q3 - Using the same resources, what is the best sensor placement position, if your team only has one network sensor and two host sensors? Why?

  ```notes
    Network Sensor
    If you have the port density, I would place it at the firewall and span one of its ports.  If that is not a possibility, it would be a span off of 10.0.1.4.  Both places get me closer to the egress point to monitor for data exfil.

    Hosts:
    I would probably put a host sensor on the mail server.  That is one of the targets for APT1.  I would monitor for the malicious email addresses associated with APT1.  The next host would be File Server 10.2.3.131.  This is based on the assumption that this is where the sensitive documents are stored.  I would start monitoring file access.
  ```

## Exercise 3.1-05: Receive and Process Baseline System  

* [Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)  
* [FTK Imager](https://learn.dcita.edu/resume_course/305624)  
* [Sysinternals Handle](https://docs.microsoft.com/en-us/sysinternals/downloads/handle)  

* Steps to verify if a file has been modified.
  * Using FTK Imager, browse to the each file and `export file hash`
  * Using PowerShell use the command `Get-FileHash -Algorithm <MD5 or SHA1> <c:/Path/to/file.exe>`
  * Do a manual comparison.  This is the quickest way since we only have to look at 4 applicaions.  Real world we would have exported a full file hash list from FTK and obained a file hash list with PowerShell then did a comparison.

* Steps to see if any new userser were added.
  * I first looked at the Users folder in FTK Imager
  * I then ran `Get-LocalUser` and compaired that list with what I saw in FTK imager.

* Steps to get Compair Registries.
  * Using FTKImager export the NTUSER.DAT from DCI Student
  * Mount the NTUSER.DAT file with Regview then browse to the various run keys
  * Using PowerShell you can use `get-itemproperty` to get the run key values from the local machine.
  * From there just do a manual comparison.  

* Steps to get Volatility profile on the image. [SANS Cheatsheet] (images\Mod3\E3-1-05\MemoryForensicsCheatSheet.pdf)  
  * Start off by running `.\volatility.exe -f E:\memdump.mem imageinfo`
    * Answer was: Win10x64_14393
* Steps to get the baseline processes
  * run `.\volatility.exe -f E:\memdump.mem --profile=Win10x64_14393 pslist`

* Steps to get the munatant handle for av64 process
  * run `handle64 -a -p av64 | findstr Mutant`
  * or `handle64 -a -p av64 | select-string "Mutant"`

* Steps to get listening UDP Ports
  * `Get-NetUDPEndpoint | select LocalAddress, LocalPort, OwningProcess` and `get-NetUDPEndpoint | Foreach-object {get-process -id $_.OwningProcess}` gave me a list of UDP Ports and the process that owns them
  * `.\volatility.exe -f E:\memdump.mem --profile=Win10x64_14393 netscan` gave me a list of Baseline UDP connections  

* I used process Explorer to get the file paths of the malicious processes.

1. Which of the following files in c:\windows\system32 have been manipulated on the current system, compared to the baseline?  
    * Runonce.exe
    * GRR.exe
2. Putty was in the original system image, but this owner decided to delete Putty.exe. What were the last 4 characters of the md5?  
    * 0Ce9 - My answer - MD5
    * 3f1b - Feedback - SHA1
3. Are there any new users on the host machine compared to the baseline? If yes, list them here (separated by commas if more than one).  
    * dciadmin  
4. Extract the registry files from the hard drive. Are there any new run key entries that don't match the baseline? If yes, what are the paths to the binary referenced by them?  
    * %LOCALAPPDATA%\av64.exe
    * %LOCALAPPDATA%\Microsoft\VMwareManager.exe
    * %TEMP%\csrs.exe  
5. What is the correct volatility profile to use on this image?  
    * Win10x64_14393  
6. Which of the following processes on the current machine has the same PID as the baseline?  
    * System
7. Are there any new suspicious processes running on the system that don't match the baseline?  
    * nc64
    * av64
    * sedsvc - Not of feedback
    * dllhost - Not of feedback  
8. What is the mutant of the first abnormal process, alphabetically?  
    * crazy123
9. Are there any processes on the current machine listening on UDP that were not in the baseline? If yes, what is the name of the process?  
    * nc64.exe
10. Using the first abnormal process (alphabetically), what is the file that started that process?
    * Task Scheduler - Mine  
    * C:\Program Files (x86)\Google\av64.exe  - feedback  
11. Using the second abnormal process (alphabetically), what is the file that started that process?  
    * vpn - Mine  
    * C:\Users\DCI Student\Desktop\Exercise\config\nc64.exe - feedback  

## Exercise 3.2-06 Perform Nmap Scan for Endpoint Identification

* [Nmap Documentation](https://highon.coffee/blog/nmap-cheat-sheet/)
* [Nmap Cheat Sheet](https://nmap.org/)  

1. Command to scan endpoint 192.168.13.17
    * `nmap -Pn 192.168.13.17`  
    * TCP 135  
2. Command to scan endpoint 192.168.13.17 and get OS
    * `nmap -Pn -O 192.168.13.17`  
    * Microsoft Windows 10
3. A command to scan endpoints 192.168.13.19 and 192.168.13.20.  
    * `nmap -Pn -O 192.168.13.19 172.168.13.20`
    * Web servers
4. Command to scan a full subnet and OS
    * `nmap -O 192.168.13.0/24`  
    * 192.168.13.32

## Exercise 3.2-07: Develop Rudimentary Ping Scan  

* [Ping Sweep with PowerShell](https://petri.com/building-ping-sweep-tool-powershell)
* [Port Checker with PowerShell](https://petri.com/building-a-powershell-ping-sweep-tool-adding-a-port-check)
* [Ping Sweep with Command Line](https://en.wikiversity.org/wiki/Computer_Networks/Ping/Sweep)
* [PowerShell Scripting Cookbook](https://web.archive.org/web/20190220192836/https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-5.1)
* [Writing Scripts with PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/ise/how-to-write-and-run-scripts-in-the-windows-powershell-ise?view=powershell-5.1)
* [Writing Batch Scripts](https://www.howtogeek.com/263177/how-to-write-a-batch-script-on-windows/)
* [Command Line Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490890(v=technet.10)?redirectedfrom=MSDN)  

* My Ping Sweep Code:

  ```PowerShell
  $IPList = 1..255 | ForEach-Object {"172.29.234.$_"}

  $ReplyResults = @()
  $i = 0
  foreach ($node in ($IPList)){
      $i += 1
      Write-Progress ???Scanning Network??? -PercentComplete (($i/$IPList.Count)*100)
      $icmpresults = ping $node -n 1 
      try {
          $ReplyResults += ((($icmpresults | Select-String "reply" | Where-Object {$_ -notlike "*unreachable*"}).ToString()).Split(" ")[2]).TrimEnd(":")
      }
      catch {
          write-host "$node is not accessable"
      }
  } 
  $ReplyResults
  ```

## Exercise 3.2-08: Perform Traffic Analysis Using Wireshark

* [WireShark Display Filters](https://wiki.wireshark.org/DisplayFilters)
* [Wireshark User's Manual](https://www.wireshark.org/docs/wsug_html_chunked/)
* [Symantec Security Response: Indicators of Compromise](https://learn.dcita.edu/system/dragonfly/production/asset_library/5d38fa054eae2a34f20452d73359e51c.pdf)

* How to find Top Talkers
  * Wireshark -> Statistics -> Conversations -> IPv4
  * Sort by Packets
  * 8.28.16.201

* Purpose of host 8.28.16.201
  * Filter Used: `ip.addr == 8.28.16.201 and http.request.method == GET`
  * Most Get Requests had K9 as the User Agent.  K9 is a free webfiltering tool offered as a home use product from BlueCoat.

* least active external/public IP address (not 204.79.197.254 and 211.149.241.70)
  * Wireshark -> Statistics -> Conversations -> IPv4
  * Sort by Packets
  * 13.107.255.14

* Huge spike in traffic
  * Wireshark -> Statistics -> IO Graph
  * 1359 = 496

* Look for executables
  * Wireshark -> File -> Export Objects -> HTTP (No Results)
  * Filter for `frame contains "exe"`
  * Found PCCleaner in some HTTP traffic
  * Tracked it down to packet TCP Stream 255
  * Actuall file was 150067.htm
  * pccleaner.exe

* Extract file
  * Wireshark -> File -> Export Objects -> Http -> 150067.htm
  * First verified that it was a binary `file 150067.htm`
  * Then made sure there wasn't any extra html data 'xxd 150067.htm`
  * Then got the MD5 checksum `md5sum 150067.htm` -> Last four `4965`
  * On the second go around, I had to look for the url that the binary was downloaded from `download.fast-files.com`

* Next stream called out to `fast-files.com`
  * Easy way was to run IOC list through pcap
    * `tcpdump -nnvXS -r /path/to/PCAP | grep -nof /Path/to/file`
  * 8. smilecare.com ?????
  * Analizing the UserAgent strings and filtering out the known good, we end up finding a user agent string of powershell. The first one was a one hit wonder the next one kept repeting.  I looked for the DNS Query that matched that traffic.
* Does the identified domain name match a known IOC for this threat?
  * 9. `Yes`
* What is the IP address of the identified domain?
  * 10. `66.77.206.85`
* What is the interval of the beacon?
  * 11. 60 seconds
  * Once I was able to identify the Malicious IP I did a filter of `ip.dst 66.77.206.85`

## Exercise 3.2-09: Analyze Obfuscated Traffic

* [File Signatures](https://www.garykessler.net/library/file_sigs.html)
* [User Agent Strings](https://www.sans.org/white-papers/33874/)
* [Malware Obfuscation Approaches](https://blog.malwarebytes.com/threat-analysis/2013/03/obfuscation-malwares-best-friend/)  

* Case Study 01
  * Extract the file yikr9jXET.jpg
    * Export object produced `JpgImageFromWireshark`

  * Extract the PNG image file transferred over HTTP with an IP in the 68.85.0.0/16  
    * `ipaddr == 10.10.0.0/16 and http`
    * led me to packet 757822 and found `q9Xik-rTnw.bin`
    * Exported it and ran `file q9Xik-rTnw.bin`
    * Then renamed it `mv q9Xik-rTnw.bin q9Xik-rTnw.png`
    * Ended up with `PngBy5ignature`

  * Identify the downloaded executable masquerading as a `Windows update`  
    * Started with `Frame Contains "Windows Update"`
    * Then tried `Frame Contains "WindowsUpdate"`  
    * Then tried `Frame Contains "Windows"`  
    * Started making some headway with `Frame Contains "Update" and Http`
    * Ended up finding `GET /msdownload/update` packet 771931
    * Best query `frame contains "msu"`
      * Answer was `Windows6.0-KB934307-x86.msu`

* Case Study 02
  * Analyze the traffic associated with the User Agent string "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.1288)"
    * First Query `http.user_agent == "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.1288)"` - Attacker IP `72.184.13.16`
    * Q1 Operating system is `Windows 10` SourceIP 172.16.128.169
  * 2 uri has `Symantec`
  * Q3 UID = `439EB29F`

* Case Study 03
  * I filterd out the known IP `172.16.128.169` and set the destination IP to the attacker `72.184.13.16`
    * query looked like `(ip.dst == 72.184.13.16) && !(172.16.128.169)`
    * Found stream 18343 and a urlencoded POST
    * Followed the stream and copied out the encoded message
    * Ran `echo <encoded message> | base64 -d` and received `getcmd=1&uid=B621A93F&=Win+10+(64-bit)&av=Symantec&nat=no&version=3.3`
      * Q1 version 3.3
  * Looking at the HTTP stream I found another base64 encoded string and decoded it.
    * Respons was `rate 60#loader http://114.80.105.136`
    * Q2 114.80.105.136
  * Q3 No

## Exercise 3.3-12 Analyze a Host to Identify Threat  

* [PowerShell_for_Responders-PowerShell_Cookbook](.\Documents\PowerShell_for_Responders-PowerShell_Cookbook.pdf)  
* [Microsoft: Getting Started with Windows PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.2)  
* [Microsoft: Windows PowerShell Programmer's Guide](https://docs.microsoft.com/en-us/powershell/scripting/developer/prog-guide/windows-powershell-programmer-s-guide?view=powershell-5.1)

* filefinder sysntax `c:\users\**10\extension.exe`

* Use psexc to enable PSRemoting
  * `psexec.exe \\172.16.12.3 -u dcistudent -password P@ssw0rd P@ssw0rd -s Powershell.exe`

* Copy an item from remote machine
  * `$Session1 = New-PSSession -ComputerName 172.167.12.3`
  * `Copy-Item -Path '<localPath>' -Destination '<remotePath>' -FreomSession $Session1 -Recurse`

* Get and compare remote file hashes with a know good list.
  * Get a list of remote hashes
    * `invoke-command -computer name 172.16.12.3 -command {get-filehash -Algorithm SHA256 c:\Windows\System32\*} | out-file ~\Desktop\RemoteFileHashes.txt`
  * Compare the file with a know list from the previous step.
    * Ended up doing a manual file comare.
      * Excel2017.exe and extrac32.exe  

1. Which malicious binaries are found on the Windows system?
    * FileHunter-Win32.exe  
    * extension.exe  
2. Based on the previous two malicious binaries, did they establish persistence within the registry?
    * No
3. Using the hashes, classify the type of malware the binaries are.  
    * Adware
4. On the remote machine, which malicious binaries are on the system?  
    * jackinthebox.exe
    * excel2017.exe
5. Which files have been changed since the baseline was made?
    * Noise.dat  
6. Which file is in the baseline and in the System32 directory?
    * recdisc.exe.mui

## Exercise 3.3-13 Analyze Hosts to Determine IOC Presence

* Started with an export of all the dns queries from wireshark
  * `tshark -r myPcap.pcapng -Y "dns and upd.dstport == 53" >> MyPcapDomains.csv`
  * From there I used Notepad ++ to do some data manipulation and took out all the MS domain which left me with 7 domain to check.
    * Found the following domains: `deebeedesigns.ca, firebirdonline.com, thecrownsgolf.org`

* Next I exported all the uri using same technique as above
  * `tshark -r myPcap.pcapng -Y "http.request.method == GET and http.request.uri" >> MyPcapURIs.csv`
  * From there I used Notepad ++ to do some data manipulation.  I removed the columns I didnt need. Then sorted Lexicographically and searched for the uris in the question.

* For the registry questions I used PowerShell
  * Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce  
  * Get-Item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-Item HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce

* To find the executable for the malicious service
  * I started by compairing the 3 services in the IOC list with what was running
    * `get-service <service name>`
  * Once I found a match, I ran `get-CimInstance Win32_Service | Where-Object {$_.name -like "*aec*"} | select Name, Status, PathName`
    * `C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe`
    * Also created a script [Get-maliciousService](https://github.com/P0w3rChi3f/Get-MaliciousServices)  

1. List all domains that the host is connecting to that match the given IOCs. Provide your answer in alphabetical order with a space between each domain.  
    * deebeedesigns.ca  
    * firebirdonline.com  
    * thecrownsgolf.org
2. Out of the following GET paths, which IOCs were requested? Select all that apply.  
    * news/media/info.html
    * SmartNav.jpg
3. What IP IOCs are present on the system?
    * 63.192.38.11
    * 65.110.1.32
    * 140.116.70.8  
4. Find all registry run keys that match IOCs. What are the executables referenced that match IOCs?  
    * rouj.exe
    * runinfo.exe
5. Find the service name that matches the IOC list. What is the binary path of the executable it references (including the executable itself)?  
    * C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe

## Exercise 3.3-14: Analyze a Security Event Log

* [Windows Logon Forensics](.\Documents\WindowsLogonForensics.pdf)

* Get Catagory of first log
  * `get-winevent -path <path\to\evtx\file> | select -first 5`
  * `get-winevent -path <path\to\evtx\file> | where {$_.id -eq "1102"} | Select TaskDisplayName`
* Get the time the log was cleared
  * `get-winevent -path <path\to\evtx\file> | where {$_.id -eq "1102"}`
* Count of event ID 4624
  * `get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4624"} | measure`
* Count of event ID 4779
  * `get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4779"} | measure`
* Earliest failed logon attempt
  * `get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4625"} | select -Last 5`
* Get Earliest failed logon attempt Logon Type
  * "(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4625"} | select -Last 1 | Select-object -expand message).split("`n") | select-string -pattern "Logon Type:""
* Analyzing Password reset
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4724"}` shows a password change attempt was made
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4738"}` shows a user account was changed.
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4724"} | Select-object -expand message).split("n") | select-string -Pattern "Password Last Set:" -context 8,0`
* Look for Privilege escalation
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4672"}`
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4732"}`
  * There were no 4728 logs
* Find the user that was elevated to Admin
  * `(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4672"} | Select-object -expand message).split("n") | select-string -Pattern "Account Name:"` -gets a list of users who were elevated
* Get event ID not related to user accounts or groups.
  * ``
* Get file name for System integrity event ID  
  * found other System Integrity event Id through Google
  * Counted how many logs there were: `get-winevent -path <path\to\evtx\file> | measure` = 206
  * Then counted how many begain with a 4: `get-winevent -path <path\to\evtx\file> | where {$_.id -like "4*"} | measure` = 203
  * then looked at what the 3 logs were that didn't begin with 4: `get-winevent -path <path\to\evtx\file> | where {$_.id -notlike "4*"}` = 6281 and 1102
  * Then looked at the 6281 logs: `(get-winevent -path <path\to\evtx\file> | select -first 1 | where {$_.id -eq "6281"} | Select-object -expand message)`

## Exercise 3.3-15: Characterize a Suspicious File

* [Malwarebytes Windows Portable Executable (PE) Analysis Tools](https://blog.malwarebytes.com/threat-analysis/2014/05/five-pe-analysis-tools-worth-looking-at/)
* [Structure of a Portable Executable (Graphic)](https://upload.wikimedia.org/wikipedia/commons/0/09/Portable_Executable_32_bit_Structure.png)
* [Structure of a Portable Executable](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN)

## Exercise 3.3-16: Become Familiar with Executable Static Analysis  

* [Kris Kendall's presentation on Practical Malware Analysis](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/viewer.html?pdfurl=https%3A%2F%2Fwww.blackhat.com%2Fpresentations%2Fbh-dc-07%2FKendall_McMillan%2FPaper%2Fbh-dc-07-Kendall_McMillan-WP.pdf&clen=1047569&chunk=true)  
* [Structure of a Portable Executable (Graphic)](https://upload.wikimedia.org/wikipedia/commons/0/09/Portable_Executable_32_bit_Structure.png)  
* [Structure of a Portable Executable](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN)  
* [Malwarefox.com: Classes/types of Malware](https://www.malwarefox.com/malware-types/)
* [Malwarebytes: Explained: Packer, Crypter, and Protector](https://blog.malwarebytes.com/cybercrime/malware/2017/03/explained-packer-crypter-and-protector/)  

## Mod 3 Review

1. NetMap - What are the subnets
2. Define the Choke points
3. Find 2nd Choke point
4. Find 3rd Choke point
5. COA 1 - Best placement for Net Sensor
6. COA 2 - Best placement for Net Sensor
7. COA 3 - Best placement for Net Sensor
8. Baseline image - get MD5 Hash (FTK)
9. BaseLine - get MD5 Hash (FTK)
10. Baseline size of file
11. Baseline Last modify date
12. Identify WS not on the Map
13. Domains that are know IOC's
14. Open ports that did not match baseline  

    * `$openTCPPorts = Invoke-command -compter (get-content computers.txt) -command {get-nettcpconnection}`  
    * `$openUDPPorts = Invoke-command -compter (get-content computers.txt) -command {Get-NetUDPEndpoint}`
    * `$openTCPPorts.localport | group | sort count`
    * `$openUDPPorts.localport | group | sort count`  

15. Banner Grab - What service was enumerated
16. Dat bat file that ws not part of baseline
17. Which process not part of baseline
18. Which service not part of baseline
19. Which file is know IoC?

## Exercise 3.3-17 Characterize Binaries

[Mandiant: Practical Malware Analysis by Kris Kendall](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/viewer.html?pdfurl=https%3A%2F%2Fwww.blackhat.com%2Fpresentations%2Fbh-dc-07%2FKendall_McMillan%2FPaper%2Fbh-dc-07-Kendall_McMillan-WP.pdf&clen=1047569&chunk=true)  
[Structure of a Portable Executable (Graphic)](https://upload.wikimedia.org/wikipedia/commons/0/09/Portable_Executable_32_bit_Structure.png)  
[Structure of a Portable Executable](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN)  
[Malwarefox.com: Classes/types of Malware](https://www.malwarefox.com/malware-types/)  

## Exercise 3.3-18: Coaxing Network IOCs

[FakeNet-NG - Next Generation Dynamic Network Analysis Tool](https://github.com/mandiant/flare-fakenet-ng)
