# Course Overview

## Course Description

* All DCI activities revolve around one central theme: identifying and communicating pre-existing or developing adversary activity in a mission commander’s network.  
* DCI analysts also are tasked with rapid deployment of indicators of compromise to detect, defend and ultimately eradicate enemy freedom of action in friendly networks.  
* This course introduces the concepts of threat agents, threats, IOCs, sensors and remediation techniques for use in DCI activities.

## Course Objectives

* Summarize the CPT mission
* Integrate threat intelligence analysis with mission owner requirements
* Choose appropriate tools and techniques for network and host reconnaissance and collection
* Analyze host and network data to identify indicators of compromise (IOCs)
* Create remediation strategies and mitigation plans of action
* Compile final reporting and perform other mission closeout activities

## Course Layout and Expectations  

* Students will be introduced to tools and provided resources for the tools that they will be using throughout the course
* Students are encouraged to ask instructors for clarification whenever necessary
* Students should collaborate with each other via the Moodle Discussion Board(s)
* Students must complete and submit their Operator Logs, both for exercises and exams
* DCI is an exercise-based course allowing for students to work collaboratively in a close approximation of a real-world environment
* Students will be tasked with performing DCI-specific duties in different real-world scenarios and so may not always be given a complete picture at the start of the exercise
* Each exercise will be followed by an instructor debrief to further emphasize processes and methodologies that students can implement in their roles
* Exercises can be repeated up to 10 times to allow students to further refine their capabilities

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

## Exercise 2.3-07: Configure and Test GRR Rapid Response for Deployment/Use  

* Fix Client Agents
  * On the GRR Server edit the `/etc/grr/server.local.yaml`  
  * run `sudo grr_config_updater repack_clients`  

## Exercise 2.3-08: Create Filesystem Artifact IOCs for GRR

* File Command used to find artifacts
  * `%%environ_systemdrive\**10{FileNames}{Extentions}`

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
