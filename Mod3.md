# Module 3  

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

  * Q6 - Private Hawker wants to use and configure the HBSS on the .3 host machine (local defender’s software) in order to monitor for threat activity. Why would it be important to use organic capabilities before we use our own?  

  ```notes
    Once configured, we can leave documentation with the customer on how to configure and monitor their own equipment.  If we used ours, we would not have anything to leave behind for the customer to use and defend with.
  ```

  * Q7 - Private Hawker wants to know why she has to monitor the network and make observations instead of immediately removing the malware from the host machine. Why is it important to monitor the network and make observations before containing and eradicating the malicious actor’s activity?  

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

* Steps to verifie if a file has been modified.
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

## Exercise 3.2-06 Perform Nmap Scan for Endpoint Identification

* [Nmap Documentation](https://highon.coffee/blog/nmap-cheat-sheet/)
* [Nmap Cheat Sheet](https://nmap.org/)  

* Command to scan endpoint 192.168.13.17
  * `nmap -Pn 192.168.13.17`  

* Command to scan endpoint 192.168.13.17 and get OS
  * `nmap -Pn -O 192.168.13.17`  

* A command to scan endpoints 192.168.13.19 and 192.168.13.20.  
  * `nmap -Pn -O 192.168.13.19 172.168.13.20`

* Command to scan a full subnet and OS
  * `nmap -O 192.168.13.0/24`

## Exercise 3.2-07: Develop Rudimentary Ping Scan  

* [Ping Sweep with PowerShell](https://petri.com/building-ping-sweep-tool-powershell)
* [Port Checker with PowerShell](https://petri.com/building-a-powershell-ping-sweep-tool-adding-a-port-check)
* [Ping Sweep with Command Line](https://en.wikiversity.org/wiki/Computer_Networks/Ping/Sweep)
* [PowerShell Scripting Cookbook](https://web.archive.org/web/20190220192836/https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-5.1)
* [Writing Scripts with PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/ise/how-to-write-and-run-scripts-in-the-windows-powershell-ise?view=powershell-5.1)
* [Writing Batch Scripts](https://www.howtogeek.com/263177/how-to-write-a-batch-script-on-windows/)
* [Command Line Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490890(v=technet.10)?redirectedfrom=MSDN)

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
  * 11. ????? I will figure it out.
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

* Copy an item from remote machine
  * `$Session1 = New-PSSession -ComputerName 172.167.12.3`
  * `Copy-Item -Path '<localPath>' -Destination '<remotePath>' -FreomSession $Session1 -Recurse`

* Get and compare remote file hashes with a know good list.
  * Get a list of remote hashes
    * `invoke-command -computer name 172.16.12.3 -command {get-filehash -Algorithm SHA256 c:\Windows\System32\*} | out-file ~\Desktop\RemoteFileHashes.txt`
  * Compare the file with a know list from the previous step.
    * Ended up doing a manual file comare.
      * Excel2017.exe and extrac32.exe
  
## Exercise 3.3-13 Analyze Hosts to Determine IOC Presence

* Started with an export of all the dns queries from wireshark
  * `tshark -r myPcap.pcapng -Y "dns and upd.dstport == 53" >> MyPcapDomains.csv`
  * From there I used Notepad ++ to do some data manipulation and took out all the MS domain which left me with 7 domain to check.
    * Found the following domains: `deebeedesigns.ca, firebirdonline.com, thecrownsgolf.org`

* Next I exported all the uri using same technique as above
  * `tshark -r myPcap.pcapng -Y "http.request.method == GET and http.request.uri" >> MyPcapURIs.csv`
  * From there I used Notepad ++ to do some data manipulation.  I removed the columns I didnt need. Then sorted Lexicographically and searched for the uris in the question.

* For the registry questions I used PowerShell
  * Get-ItemPropery HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-ItemPropery HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce 
  * Get-ItemPropery HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-ItemPropery HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce

* To find the executable for the malicious service
  * I started by compairing the 3 services in the IOC list with what was running
    * `get-service <service name>`
  * Once I found a match, I ran `get-CimInstance Win32_Service | Where-Object {$_.name -like "*aec*"} | select Name, Status, PathName`
    * `C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe`  
