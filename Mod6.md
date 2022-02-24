# Module 6: Recover Stage Operations  

## Exercise 6.1-01: Re-baselining a Network  

[Top 1000 NMAP Ports](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/)
[WinRM Service Port](https://docs.microsoft.com/en-us/archive/blogs/christwe/what-port-does-powershell-remoting-use)
[Grep Man Page](http://linuxcommand.org/lc3_man_pages/grep1.html)
[dc3dd Tool Usage](http://manpages.ubuntu.com/manpages/bionic/man1/dc3dd.1.html)
[Removing the GRR Agent](https://grr-doc.readthedocs.io/en/v3.2.1/deploying-grr-clients/on-windows.html)
[Retrieving Windows Event Logs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1)

1. The local defenders have added a firewall that is blocking ping and a basic scan that will return a list of ports that are all filtered if not open. What IP address needs to be added to the network workstations’ baseline?
    * `nmap -sP 172.29.234.0/24 -oN PingSweep.txt`  
    * `nmap 172.29.234.0/24`  
    * 172.29.234.5  
    * On Round 2, I just used a pingsweep from Win10.

        ```PowerShell
        $IPList = 1..255 | ForEach-Object {"172.29.234.$_"}

        $ReplyResults = @()
        $i = 0
        foreach ($node in ($IPList)){
            $i += 1
            Write-Progress “Scanning Network” -PercentComplete (($i/$IPList.Count)*100)
            $icmpresults = ping $node -n 1 
            try {
                $ReplyResults += ((($icmpresults | Select-String "reply" | Where-Object {$_ -notlike "*unreachable*"}).ToString()).Split(" ")[2]).TrimEnd(":")
            }
            catch {
                write-host "$node is not accessable"
            }
        } 
        $ReplyResults

        $IPSearch = "172.29.234.9", "172.29.234.2", "172.29.234.5","172.29.234.16"

        foreach ($IP in $IPSearch){ $IP -in $ReplyResults; Write-host $IP}
        ```

        * Results:  

        ```Results
        False
        172.29.234.9
        False
        172.29.234.2
        True
        172.29.234.5
        False
        172.29.234.16
        ```

2. How many workstation IP addresses can be verified to have WinRM running?  
    * Regex to remove "Host is up (0.00080s latency)."  
        `(\d.\d\d\d\d latency)`  
        `Host is up ().`
        `\n\r`
        Saveded file on desktop as "IPList.txt"
    * $enabledConnections had 1 item.

    * ```PowerShell
        $IPList = Get-content .\IPList.txt
        $enabledConnections = @()
        foreach ($IP in $IPList) {
            try {
                $winRM = Test-WSMan -ComputerName $IP
                if ($Null -ne $winRM) {$enabledConnections += $IP   
                } # Close IF
            } # Close Try
            Catch {
                if ($Error[0].ToString() -match "The client cannot connect to the destination")
                {Write-Host "$IP does not have WinRM enabled"}
            } # Close Catch
        } # Close foreach
        ```  

    * Expnanding on my code from Q1:
        * `foreach ($IP in $ReplyResults){Test-WSMan -computerName $IP -errorAction SilentlyContinue}`

3. Run a scan on the 172.16.8.9 address. With the scan results given, could you guarantee that the WinRM port was running on the server?  
    * `nmap 172.16.8.9` - Yes
    * `nmap 172.16.8.9 -p 5985,5986,80,443` - No  
        * 80 - Closed  
        * 443 - Closed
        * 5986 - Closed
        * 5985 - UNK  
    * Round 2:  Connections not working with NMap and I did a `Test-WSMan` on the server and appears to be running.  
    * Was able to `Enter-PSsession` to the server.
4. The first step on the server is checking to see if WinRM is stopped from accepting remote connections. When complete, run check_winrm.exe which is on the Windows server's C:\. What was the response from the executable when successful?  
    * WinRM Failed
        * Had to use "Get-Credential"
    * `.\psexec.exe \\172.16.8.9 -u Administrator -password P@ssw0rd -s Powershell.exe`  
    * initial `.\verify.exe` produced 0 results

    * ```PowerShell
        disable-Psremoting -force
        stop-service WinRM
        ```

        * w1nrmvd
    * Round 2: Just loged onto the Server and ran:  

        ```PowerShell
        disable-Psremoting -force
        stop-service WinRM
        c:\check_winrm.exe
        w1nrmvd
        ```

5. The next step is to remove any traces of the GRR agent from the box. Once complete, run the executable to verify GRR is removed. What is the code that the executable provides once you have removed the agent?

    ```Powershell
        stop-service "GRR Monitor"  
        sc delete "GRR Monitor"  
        get-childitem c:\ -recuse -force -ErrorAction SilentlyContinue -include grr*
        remove-item HKLM:\Software\GRR -force 
        remove-item c:\Windows\system32\grr -recurse -force  
        remove-item c:\Windows\system32\grr_installer.txt -force
        c:\verify.exe 
    ```

    * R3m0vedG44  

6. What source ports have been used by the CPT’s Windows 10 host?  
Note: Look for IP 172.16.12.3.  There are 12 total results, but select only from the following:  
    * `get-winevent Microsoft-Windows-WinRM/Operational | select-object -expandProperty message | select-string "172.16.12.3"`  - NoGo
    * `get-winevent "Microsoft-Windows Firewall with Advanced Security/Firewall" | select-object -expandProperty message | select-string "172.16.12.3"` - NoGo
    * `Foreach ($log in (get-winevent -listlog *)){get-winevent -logname $log.logname | select-object -expandproperty message | select-string "172.16.12.3"}` - GO  
    * `Foreach ($log in (get-winevent -listlog *)){(get-winevent -logname $log.logname | select-object -expandproperty message).split("n") | select-string "172.16.12.3"}`  

    * Finally did an XML Filter:

        ```XML
            <QueryList>
                <Query Id="0" Path="Security">
                    <Select Path="Security">*[System[(EventID=4624)]] and *[EventData[Data[@Name='IpAddress'] and (Data='172.16.12.3')]] and *[EventData[Data[@Name='IpPort'] and (Data=56842 or Data=65499 or Data=65497 or Data=50726)]]</Select>
                </Query>
            </QueryList>
        ```

    * 65497 and 50726
    * [Win Event Log Filtering using Hashtables](https://docs.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-5.1)  
    * PowerShell Filter by HashTable:  
        `(Get-WinEvent -FilterHashTable @{LogName='Security'; ID='4624'; Data='172.16.8.9'} | Select-Object -ExpandProptery Message).split("n") | Select-String -Pattern "Source Port:"`
7. What impersonation level was found to be used by the remote logon from the CPT’s Windows 10 host?
    * %%1833

8. What does the above impersonation level answer represent?
    * [Impersonate - Impersonate-level COM impersonation level that allows objects to use the credentials of the caller. This is the recommended impersonation level for WMI calls.](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)  
    * Credentials of the caller are being used.  Similar to Single Sign-O
    * [Impersonation levels](https://thisismyclassnotes.blogspot.com/2019/12/windows-account-logon-impersonation.html)

9. How many times, before today, does the Instance ID of 4624 show up corresponding to the IP address 172.16.12.3?  
    * 61

10. [My Reort](./Documents/Mod6-1-01-10.txt)  

11. Using dc3dd, wipe the mission data from the IR Drive and verify with xxd. Use the hex pattern 0xdac1.  What value is represented at the 902nd byte after running xxd?  

    * `lsblk` to find the mounte device
    * `umount -l /dev/sdb1`  
    * `dc3dd wipe=/dev/sdb pat=dac1`
    * `xxd -l 1 -s 901 /dev/sdb1`
        * c1

## Mod6 Review

1. Wireshark capture, Identify IP's producing network traffic
2. Identify external IP connection
3. How many Domain IP to external IP
4. What Domain IP is showing up that is not document
5. Version of WinRM
6. Remove Agent get Code
7. Get code from stoped services
8. Source ports
9. Occurance of ID
10. Report of Recommendations
11. Value of 320th byte  
