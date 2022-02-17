# Module 2: Mission Planning  

## Exercise 2.3-06: Forensically Wipe Media for Deployment/Use

* dc3dd command  
  * dc3dd wipe=/dev/sdc tpat="Media wiped on 20220106 by James Honeycutt"  
  * xxd -l 512 /dev/sdc
  * dc3dd wipe=/dev/sdc pat=12345678
  * xxd -l 1 -s 45983 /dev/sdc  

* Format Disk
  * fdisk /dev/sdc
    * n -> 1 -> 1024 -> +4.3G -> w  
  * mkfs -t ext4 /dev/sdc  

1. Which course of action is the BEST approach to prepare your storage media for storing new incident data?
    * Use a software tool to forensically wipe the drives.
2. Which course of action is the BEST approach to prepare your storage media for storing new incident data for this mission?  
    * Obtain new unused drives to obtain the required data.  
3. Review the data returned by EnCase Forensic Imager that indicates the drive was successfully wiped. In the space below, enter the total number of sectors wiped.  
    * 10485760
4. Using EnCase enter the last 4 characters of the MD5 hash of the drive you just wiped?  
    * 46C9
5. Once the above steps are completed, in the space below, enter the byte value for the 45,984th byte on the disk?  
    * 78
6. Using the tool of your choice create a 4.3 GB partition on the 5 GB drive. Were you able to successfully partition and format the 5 GB drive?
    * Yes
7. After formatting the partition with the ext4 file system record the number of inodes in the space provided below.  
    * 327680 - Was marked wrong

## Exercise 2.3-07: Configure and Test GRR Rapid Response for Deployment/Use  

* Fix Client Agents
  * On the GRR Server edit the `/etc/grr/server.local.yaml`  
  * run `sudo grr_config_updater repack_clients`  

1. Were you able to successfully enroll the Windows 10 x64 machine to the GRR server?
    * Yes
2. Briefly describe what you did to complete the exercise and why it had to be done. - Was marked wrong
    * I had to edit the /etc/grr/server.local.yaml file on the GRR Server then run, sudo grr_config_updated repack_clients to repack the clients.  I was able to download and install the agent after that.
3. When trying to locate artifacts on one system using GRR, should you use a flow or a hunt? 
    * Flow
4. Using GRR, locate and examine the hosts file of the Windows 10 x64 machine. What is the size of the hosts file in bytes?
    824 Bytes
5. Using GRR, run a Registry Finder flow. What .exe is in the Run folder?
    * OneDrive

## Exercise 2.3-08: Create Filesystem Artifact IOCs for GRR

* File Command used to find artifacts
  * `%%environ_systemdrive\**10{FileNames}{Extentions}`

1. Which executable files are on the system after running the CTE provided executable?  
    * AdobeUpdater.exe
    * wuauclt.exe  
    * iTunesHelper.exe  
2. What are the last four characters of the MD5 hash value for the binary “AdobeUpdater.exe?”  
    * 598f (8abc459525f1918d399248252ec0598f)  
3. The file size for the binary file “AdobeUpdater.exe” is how many bytes?  
    * 5435706
4. Find the latest modification date/time for the binary “AdobeUpdater.exe”. (Marked wrong - Is correct)
    * 2017-08-14 03:58:26

## Exercise 2.3-09: Create Memory and Registry Artifact IOCs for GRR

* [GRR Link](https://grr-doc.readthedocs.io/en/latest/)
* [ReKall Link](https://rekall.readthedocs.io/en/latest/plugins.html)
* [ReKall Plugins](http://www.rekall-forensic.com/documentation-1/rekall-documentation/plugins)
* Registry Command used to find artifacts  
  * AnalyzeClientMemory -> `pslist` for Process Lists
  * AnalyzeClientMemory -> `Users` to enumerate users
* Find muntants with Handle64
  * `.\handle64.exe -a | findstr Mutant`

## Exercise 2.3-10: Install Security Onion and Test Configuration

* [Security Onion Install](https://github.com/Security-Onion-Solutions/security-onion/wiki/Installation)  
* [Security Onion Cheatsheet](https://github.com/Security-Onion-Solutions/security-onion/wiki/Cheat-Sheet)  
* [Security Onion Produciton Deployment](https://github.com/Security-Onion-Solutions/security-onion/wiki/ProductionDeployment)  
* [Security Onion Post Depoyment](https://github.com/Security-Onion-Solutions/security-onion/wiki/PostInstallation)  

## Exercise 2.3-11: Use Bro to Carve Data

* [Zeek Logging](https://docs.zeek.org/en/master/log-formats.html)
* Default Zeek PCAP location:
  * /opt/samples/markofu
* TCPReplay Eample
  * 'sudo tcpreplay -i eth1 <path to PCAP> -t'
* Bro-cut example
  * `cat /nsm/bro/logs/current/files.log | bro-cut -d ts fuid tx_host rx_host filename mime_type md5`  

## Exercise 2.3-12: Create Network Traffic IOCs for Snort  

* [Zeek Log Format](https://docs.zeek.org/en/master/log-formats.html)  
* [WireShark Documentation](https://www.wireshark.org/docs/)  
* [Snort Documentation](https://snort.org/documents)  
* [TCPReplay Documentation](https://linux.die.net/man/1/tcpreplay)  
* Edit the Snort config file to read `local.rules`etc  
  * `vim /etc/nsm/so-sensor-eth1/snort.conf`  
  * uncomment `local.rules` under #7  
  * also change 'TCP Checksum Mode' from All to None
* Now I can add my custom rules to `local.rules`  
  * `/etc/nsm/rules/local.rules`  
* Then test the rules  
  * `sudo snort -T -i eth1 -c /etc/nsm/so-sensor-eth1/snort.conf`  
* Use this command to monitor Snort  
  * `snort -d -l /var/log/snort/ -h 10.0.0.0/24 -A console -c /etc/snort/snort.conf`  

1. Once you have navigated to where the pcap file is located in SecOnion, what is the syntax for Tcpreplaying the pcap provided at top speed?  
    * `tcpreplay -t -i ens34 <pcap>`
    * `tcpreplay --topspeed --intf1=ens34 <pcap>`  
2. After running the pcap through Tcpreplay, how many successful packets were there?  
    * 12586  
3. Given two of the malicious domain names, what is the last domain name found in the pcap?  
    * news.hqrls.com  
4. Given one malicious IP address, what is the last malicious IP address found in the pcap?  
    * 143.89.35.7

## VIM Shortcuts  

* Search and replace
  * `:s/search/replace` - first occurence in each line  
  * `:s/search/replace/g` - All occurences on each line  
* Add a string to the end of the line
  * `:%norm A*` - Regular Text
    * % = For Every Line  
    * norm = type the following commands  
    * A = Append "*" to the End of the line  
  * `%s/$/\=line('.')` - Number sequences  
    * % = apply to entire buffer
    * s = substitute
    * /$ = search for end of line
    * /\=line('.')-1 = replace with linenumber - 1

* Visual Block editing
  * `ESC` to enter "command mode"  
  * Use `Ctrl+V` to enter visual block mode
  * Move `Up/Down` to select the columns of text in the lines you want to comment.
  * Then hit `Shift+i` and type the text you want to insert.
  * Then hit `Esc`, wait 1 second and the inserted text will appear on every line.  
* Moving within a file
  * $ = End of line  
  * 0 = Begining of line  

## Walkthrough  

sudo vim iocips.txt
sodo vim iocdomains.txt
enter visual block mode (ctrl-V)
shift i
alert ip andy any -> any (msg: "Bad domain found)
enter visual block mode (ctrl-V)
end key
A
convert dots to multiple content feilds
`:%s/\./"; content:"/g`

Set the SID number
`:let @a=1001000 | %s/ReplaceMe/\=''.(@a+setreg('a',@a+1))/g`

Test the rules
  `snort -T -c /etc/nsm/rules/local.rules`
sudo rule-update

TCP Replay
`sudo tcpreplay -T -i eth1`  

## Exercise 2.3-13: Use PowerShell to Collect Data  

* Pingsweep
  * `1..255 | foreach {test-connection -count 1 10.10.10.$_}`
  * `start-service winrm`
  * `set-item wsman:\localhost\client\trustedhosts 10.10.10.40`
  * `enter-pssession 10.10.10.40`
* Registry Runkeys
  * Get-ItemPropery HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-ItemPropery HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce  
  * Get-ItemPropery HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  * Get-ItemPropery HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
* Search for scheduled tasks
  * `Get-ScheduledTask * -taskpath \* | select-object TaskName -ExpandProperty Actions | Where-object -like "*start.bat*"`  
* Get the disk information using get-wmiobject
  * `Get-WmiObject -class Win32_LogicalDisk`  
  * `Get-CimInstance -ClassName Win32_LogicalDisk`  
* Get a list of network connection
  * `Get-NetTCPConnection`  
* Look for missconfigurations
  * `Get-EventLog -Newest 100 -Logname System -InstanceID 414 | Select-Object -ExpandProperty Message | Group-object | Select-Object -ExpandProperty Group`  
  * `Get-WinEvent -LogName System | Where-Object {$_.id -eq "414"}`  
*Allow RDP Connections  
  * `Set-ItemProperty -Path ‘HKLM:System\CurrentControlSet\Control\Terminal Server’ -Name “fDenyTSConnections” -Value 0`  

## Module II Review  

* Parsing pcap with IOC files
`tcpdump -nnvXS -r /path/to/PCAP | grep -nof /Path/to/file`  