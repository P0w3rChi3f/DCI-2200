# Module 5: Protect Stage Operations  

## Exercise 5.1-01: Provide Situation Report, Timeline and Operator Log of Activity Exercise

1. During host discovery and enumeration, what two suspicious binaries were found on the Windows system? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  
    * FileHunter-Win32.exe
    * extension.exe
2. What type of malware are the two suspicious binaries found on the Windows system? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  
    * Adware  
3. What file was changed on the host machine since the baseline was made? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  
    * Noise.dat
4. On the Windows machine, what three domains on the IOC list were contacted by the host? (Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)  
    * thecrownsgolf.org
    * deebeedesigns.ca
    * firebirdonline.com
5. What three IP IOCs were identified on the host machine? (Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)  
    * 63.192.38.11  
    * 140.116.70.8
    * 65.110.1.32  
6. Were these files located on a host machine during the operation?(Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)  
    * Yes
7. The Microsoft Edge browser attempts to connect to which URL? (Exercise 4.1-01: Investigate a False Positive)
    * https://youtu.be/dQw4w9WgXcQ  

## Exercise 5.1-02: Provide SITREP and IOCs Identified for NETOPS  

[SitRep Template](Documents\SitRep.docx)

### Case Study 02-01  

1. Use Nmap to scan the Class C network segment for 192.168.13.1. Which ports are open for the endpoint 192.168.13.17?  
    * 135
2. Which host is most likely a workstation?  
    * 192.168.13.32
3. Per Exercise 3.2-08 Question 1: Based on Total Packets, what is the most talkative external/public IP address?  
    * 8.28.16.201
4. Was an executable downloaded? Enter the name of the downloaded executable. If there is no evidence an executable was downloaded, enter "No".  
    * pccleaner.exe
5. What is the IP address of the domain for "smilecare.com?"  
    * 66.77.206.85
6. What is the interval of the beacon?  
    * 60 seconds
7. List all domains that the host is connecting to that match the given IOCs. Provide your answer in alphabetical order with a space between each domain.  
    * deebeedesigns.ca  
    * firebirdonline.com  
    * thecrownsgolf.org
8. Which IOC’s were requested through the GET requests in the traffic capture?  
    * news/media/info.html
    * SmartNav.jpg
9. Find the service name that matches the IOCs. What is the full path of the executable it references (including the executable itself)?  
    * Service name aec
    * C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe
10. Use GRR to perform analysis on the first system. Which binaries are found on the Windows system?  
    * FileHunter-Win32.exe
    * extension.exe
11. Was persistence established in the registry?  
    * No

### Case Study 02-02  

1. [Mod5 SitRep](Documents/Mod5-SitRep.docx)

## Exercise 5.1-03: Select Appropriate Courses of Action to Mitigate Threats

### Case Study 03-01

[Mitigation Strategies](Documents/Mitigation_Strategies_2017_Details_0.pdf)  
[Mitigation Table](Documents/Ex5.1-06-Mitigation-Table.xlsx)  

[Mimikatz](https://attack.mitre.org/software/S0002/)  
[Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)  
[Poison Ivy: Assessing Damage and Extracting Intelligence](https://www.mandiant.com/resources/poison-ivy-assessing-damage-and-extracting-intelligence)  
[ASD - Mitigation Details](https://www.cyber.gov.au/acsc/view-all-content/publications/strategies-mitigate-cyber-security-incidents-mitigation-details)  

1. I would deploy a HIPS/HIDS solution to help prevent/detect Poison Ivy and User Training.  The malware gets onto the system through social engineering.  Once on the system, it starts the default web browser in the background and injects itself into that process.  Chances are the browser will be whitelisted and connections to the internet will look legit, so web filtering is out. Training the users not to receive things from strangers and backing that up with the HIDS/HIPS technology seems to be the better route.  

        *** Email Content Filtering ***

2. The report gives us a list of IPs and Domains to black list.  Starting with this information we could implement web content filtering.  We could also add a proxy and force all web traffic through it, making it harder for the C2.  

        *** NIDS/HIDS, Application Whitelisting ***

3. We could use a Web Content filter here to detect data leaving our network.  We could set up some fake data (canaries) to alert us that data exfiltration was attempted.

        *** Automate dynamic analysis of email and web content run in a sandbox ***

4. I will have to go with User Training on this one.  There are so many ways mimikatz can be delivered that we need to turn our users into human sensors.

        *** Application Whitelisting, endpoint detection ***

5. I would restrict admin privileges.  limiting these permissions and only using these permissions as needed will limit the number of passwords, hashes, cache, etc that it will collect.  

        *** Restrict Admin privileges, disable local admin, multi-factor Authentication ***

6. I would deploy an OS generic exploit mitigation to help protect the memory where the hashes are located.  

        *** restrict Admin Privileges ***

7. Same a question 5.   Stop admins from logging in and only running applications as admin when necessary.  

        *** Anything with Passwords ***

### Case Study 03-02  

1. It can still be recommended.  

        *** This may allow the malware to reach our endpoints. So we will have to rely more heavily on endpoint protection (AV, EDR, etc). ***
        *** User Training ***

2. We could recommend OS generic exploit mitigation instead, it has an upfront cost of low.  

3. We would need to find a different solution, maybe like using the host based firewall to filter traffic  

### Case Study 03-03  

1. Using the documents, I would opt to re-installing the OS  
2. I would need to locate the dll and remove it, or re-install the OS.  
3. I would probably refer to the business continuity plan and force a password reset enterprise-wide.
4. Identify the correct order of operation and provide your rationale
    * Verify installed programs - this will help with validating services and network traffic
    * Verify service list - should match up with OS and Installed programs
    * Run packet capture - to help identify unknown processess and see if they are reaching out to the internet
    * Kill active processes - Most applicatons will need to be inactive before removal
    * Remove abnormalities - Finally remove the abnormality

            ```Notes
                Kill active processes
                Verify service list
                Verify installed programs
                Remove abnormalities
                Run packet capture
            ```

## Exercise 5.1-04: Risk-Mitigation Tools and Techniques  

[OpenVAS Guide](https://www.kali.org/blog/configuring-and-tuning-openvas-in-kali-linux/)  
[PowerShell Guide](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2022-ps&viewFallbackFrom=win10-ps)  
[.Net Framework Objects](https://docs.microsoft.com/en-us/dotnet/api/system.net?view=netframework-4.7.2)  

### Case Study 04-01  

1. From the set of scans, which IP address has the highest-severity vulnerability number and what is the value?  
    * 10.10.10.13 and 6.4
2. Which IP address, or range of IP addresses, has the vulnerability "CGI Scanning Consolidation"?
    * 10.10.10.13 (Had to view log sevearity, and 10.10.10.10 & 10.10.10.13 came up)

### Case Study 04-02  

1. For 10.10.10.10: List the total amount of high and medium severity vulnerabilities that are reported.  
    * 8 (levels=hm and 10.10.10.10)  
2. List the total amount of vulnerabilities that are fixed by vendor patches.
    * 4  `solution_type=VendorFix`
3. List how many total vulnerabilities have workarounds.
    * 1
4. List how many total vulnerabilities require mitigation.  
    * 4  
5. What is the highest-severity vulnerability, and on which IP address is it?
    * 10 and 10.10.10.13 (Q0D was Higer)

### Case Study 04-03  

* (10.10.10.10 is the Voting Server)  

1. How many critical risks did MBSA find?
    * 4
2. How many user accounts had blank or simple passwords?
    * 3
3. How many shared folders are present on the system?  
    * 2
4. Is Windows Firewall enabled or disabled?
    * Enabled
5. What should RestrictAnonymous be set to for the best security?  
    * 2
6. From the following, which are the recommended Audit options in the Audit Policy. Select all that apply.  
    * Audit account logon events

### Case Study 04-04  

1. What is the process name listening on port 21 on 10.10.10.10?
    * `Get-NetTCPConnection | select LocalAddress, LocalPort, RemoteAddress, RemotePort, state, @{name="Process"; expression={($_.OwningProcess | foreach {get-process -id $_}).ProcessName}}`  
    * FileZillaServer
2. What is the PowerShell command to create a firewall rule?
    * New-NetFirewallRule  
3. How many users are registered on the SQL Server (IP 10.10.10.11)?  
    * `Invoke-command -computername 10.10.10.11 -scriptblock {Get-localUser | selct Name}`  
    * 7 Total 3 Non-builtin
4. What command would be used to modify the password of a local user?  
    * `Set-localUser -Name <UserName> -Password (ConvertTo-SecureString -AsPlainText '<PassWord>' -Force)`
5. What .net framework object would be used to download and upload FTP files?  
    * System.Net.Webclient

## Exercise 5.1-06: Provide Risk Analysis Based on an RMP

[APT1](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units)
[NIST 800-30: Risk Analysis Process](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/viewer.html?pdfurl=https%3A%2F%2Fnvlpubs.nist.gov%2Fnistpubs%2FLegacy%2FSP%2Fnistspecialpublication800-30r1.pdf&clen=826897&chunk=true)
[ASD - Mitigation Details](https://www.cyber.gov.au/acsc/view-all-content/publications/strategies-mitigate-cyber-security-incidents)  

[Mitigation Strategies](Documents/Mitigation_Strategies_2017_Details_0.pdf)  
[Mitigation Table](Documents/Ex5.1-06-Mitigation-Table.xlsx)  

1. Email content filters help with malicious documents in email, but there are other ways to move documents in and out of the environment.  Using a cloud storage provider, for example.  A web content filter can scan the document, coming to or from the storage area, for malicious content.  Web filtering content also helps protect against malicious sites, this would help mitigate a watering hole attack.  
2. Yes, this is a risk.  If an attacker could get on a machine where the local admin was logged in, steal the admin hash or password, the attacker could move laterally through the network.  If this environment is in a Windows domain, there is a free solution to mitigate this risk, the solution is LAPS.  It stands for Local Administrator Password Solution.  What it does is allow AD to manage the passwords for the local administrator on each machine.  It creates a random password and changes it every 30 days (by default).  The risk here is a machine that was synchronized with AD loses its trust relationship and the local admin password is changed and does not work.  In this situation, you will most likely lose the data on that machine.  If this is a Linux environment, there are tools you can purchase that are similar to LAPS.  
3. You are blocking spoofed emails from your organization, but there are tools (30 min email) that are legitimate that an attacker can use to send a phishing email from.  If crafted well enough, it could trick the user into clicking a link, or opening an attachment.  
4. Blacklist will help stop the execution of known malicious applications, but it will not stop the unknown malicious applications.  To accomplish that, the organization would need to implement a whitelist solution.  Meaning blocking everything unless you verify it is non-malicious.
5. Links, Facebook, and Twitter can be used as a vehicle to deliver malicious links to the organization.  There is a potential risk of someone (likely someone of importance) being profiled. Once profiled a well-crafted message or post would be sent with a link to "learn more".  This link has the potential of sending the user to a site that could deliver a malicious payload to the individual.  This is a type of Watering Hole attack.  

## Exercise 5.1-08: Generate and Implement an RMP for a Network

[Nmap guide](https://nmap.org/)

1. Using the information obtained during your vulnerability assessment and network enumeration, what is the perceived threat to the Maryland Board of Elections?

    * Weak Passwords across the Voting Server, Mail Server and Voting Database Server.
    * Some Ports were possible open to attack and needed to be secure.
    * Voting Server, Mail Server and FTP service each had critical services which need to be running to make sure the voting took place.
    * FTP Server had accounts which did not have password; default password needed to be changed
    * The Firewalls were not enabled across the servers.
    * Key files especially the Voting Database, mysql  and htdocs for web were not backed up.

2. List the perceived impact to the mission represented by each of the following Cyber Key-Terrain:

    * Voting Server – Loss would prevent website from functioning for voters. Stores votes on Voting Database Server
    * VoterDB - Stores Voting Data. Loss of tally collected would have affected the Voting overall 
    * Email Server -  Loss of confirmation Emails for Votes and any help for voters 
    * FTP Server – Loss of any critical backup files, and data that would be needed to keep the Voting operation running.

3. If you received any email notifications, what were they and how did you fix the issue?

    * Loss of Service. Check service using PowerShell:  
    * Get-Service –Name <name of Service>
    * Start-Service –Name <name of Service>
    * Loss of data file – Restore from the Backup Server

4. The web developer has created a means of easily managing the users included in the election. This file needs to be found and secured to prevent potential tampering, what is the file name?

    * C:\xampp\htdocs\create.php

## Mod5 Review

* 7-32 already completed
* 2.3-06
* 2.3-07
* 2.3-08
* 2.3-12
* 3.1-05
* 3.2-06
* 3.3-12
* 3.3-13
* 4.1-02
* 5.1-03
* 5.1-04
* 5.1-05
* 5.1-08
