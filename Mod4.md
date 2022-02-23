# Module 4: Secure Stage Operations  

## Exercise 4.1-01: Investigate a False Positive

[Symantec Indicators of Compromise](.\Documents\SymantecIndicatorsofCompromise.pdf)  

* Chrome x86 hash values  
  * `https://strontic.github.io/xcyclopedia/library/chrome.exe-9586D6F3312D6A78A743DC51C67C3A7F.html`  

## Exercise 4.1-02: Investigate a True Positive

* Make sure to hash all the binarys to find similar files.
* List all run keys

* Static way of finding the IP
  * `strings64.exe .\ituneshelper.exe | select-string -pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?"`

  * `(get-content <path/to/file/including/binarys> | select-string -pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?").Matches.Value`  

* Evidence of network traffic from ituneshelper Running malware
  * `netstat -naob | select-string "Ituneshelper" -context (1,0)`

  * `Get-NetTCPConnection | select LocalAddress, LocalPort, RemoteAddress, RemotePort, state, @{name="Process"; expression={($_.OwningProcess | foreach {get-process -id $_}).ProcessName}} | foreach {get-process -id $_}).ProcessName}} | select-string -pattern "ituneshelper"`

1. Identify if there are indicators of compromise in the registry.  
    * MattIsAwesome - Mine
    * LastEnum - Mine
    * Yes, there is a registry value that gets added to the system. - Feedback  
2. If you identified IOC's, what group of keys appears to be modified?
    * HKCU:\Software\Microsoft\Windows\CurrentVersion\Run - Mine
    * The Current User’s Run Key (HKCU) - Feedback  
3. List the values that may be IOC's.  
    * %LocalAppData%\MattIsAwesome.exe - Mine  
    * MattIsAwesome, ItunesHelper, (LastEnum) - Feedback  
4. Identify any files that could be indicators of compromise. Include the absolute paths.  
    * c:\Users\DCI Student\AppData\local\MattIsAwesome.exe - Mine
    * MattIsAwesome.exe was added in C:\Users\DCI Student\AppData\Local -Feedback  
    * ituneshelper.exe was added in C:\Users\DCI Student\AppData\Local\Temp -Feedback  
    * Note: vmwaremanager.exe was added in c:\users\DCI Student\Local\Microsoft -Feedback  
5. Is there evidence that ituneshelper could generate any network traffic? (Yes or No)  
    * `strings64.exe .\ituneshelper.exe | -pattern "get(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?`  - Mine  
    * 10.10.10.137 - Mine  
    * Yes - Feedback  
6. What is the private IP address the malware is trying to reach out to?
    * 10.10.10.137 - Mine
    * The malware attempts to contact 10.10.10.137 - Feedback  
7. Is this activity characteristic of APT1 activity?  
    * Yes. The artifacts from this malware match the characteristics of APT1.

## Exercise 4.1-03: Analyze Network Traffic to Identify Beacon

[Wireshark: Display Filters](https://wiki.wireshark.org/DisplayFilters)  
[Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)  

* beacon that has a set interval between each beacon
  * `(tcp.dstport == 21) && (tcp.flags.syn == 1) && !(tcp.flags.ack == 1)`  - 66.220.9.50

* Beacon at a random interval
  * `icmp.type == 8` payload appears to be a normal ICMP  
  * 184.168.221.35 - 2-10m - icmp

* find relitive start (I ctf'd this question)
  * `(tcp.flags.syn == 1) && !(tcp.flags.ack == 1) && (ip.dst == 204.16.139.24)`

* Ended up starting by looking for URL IOCs
  * `tcpdump -nnvXS -r ./beacons.pcapng | grep -nof ./URL.txt`
    * kayauto.net
    * gobroadreach.com

* Use IO graph to find becon
  * create filters for HTTP, 443, icmp, ftp

## Exercise 4.1-04: Deploy GRR Agent  

[GRR Rapid Response Documentation](https://grr-doc.readthedocs.io/en/latest/)
[Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal?redirectedfrom=MSDN)
[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)  

* Pull binary from GRR via invoke-webrequest (Binary had issues)
  * `$session = New-PSSession -Computer 172.16.12.6 -credential (Get-Credential Administrator)`  
  * `Invoke-Command -session $session -command {Invoke-webrequest -URI <path to exe> -outfile c:\users\Administrator\downloads\grr.exe -credential (get-credential dcistudent)}`  

* Downloaded my wks and copied it over.
  * `$session = New-PSSession -Computer 172.16.12.6 -credential (Get-Credential Administrator)`
  * `copy-item .\<file> c:\users\Administrator\Downloads\<file Name> -tosession $session`
  * `invoke-command -session $session -command {Start-process -path c:\users\administrator\downloads\<exe file name> -wait}`

  * Remove GRR from a machine
    * `stop-service "GRR Monitor"
    * `sc delete "GRR Monitor"` or pwsh v6 or higher `remove-service "GRR Monitor"`
    * `remove-item HKLM:\Software\GRR\* -recurse`
    * `remove-item c:\Windows\system32\grr -recurse -force`
    * `remove-item c:\Windows\system32\grr_installr.txt -force`

  1) kernel version of the Windows Server Client
     * `invoke-command -session $session -command {(Get-CimInstance win32_Operatingsystem).version}` - 10.0.14393
  2) the last four characters of the MD5 hash for the file wdboot.sys
     * c:\windows\ELAMBKUP\WdBoot.sys
     * c:\windows\system32\drivers\WdBoot.sys - 2c2d
  3) the size of the hosts file
     * `invoke-command -session $session -command {get-item c:\windows\system32\drivers\etc\hosts}` - 824
  4) what is the only added username on the remote system
     * `invoke-command -session $session -command {(get-localuser).name}`  

## Exercise 4.1-05: Create a PowerShell Script to Collect Data from Multiple Systems  

[Microsoft PowerShell: Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-5.1)  
[Microsoft PowerShell: About Arrays](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_arrays?view=powershell-5.1)  
[Created Get-DCIBaseline Script](https://github.com/P0w3rChi3f/Get-Baselines/blob/main/Get-DCIBaseline.ps1)

## Exercise 4.2-06: Identify Data Exfiltration Artifacts on a Windows System

[List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)  
[Alternate Data Streams in NTFS (PowerShell)](https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs)  
[PowerShell Check File Headers](http://learningpcs.blogspot.com/2012/07/powershell-v3-check-file-headers.html)  
[PowerShell Get-Content Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)  
[Get Hex Dumps of Files in PowerShell](https://www.itprotoday.com/powershell/get-hex-dumps-files-powershell)  
[Started my Hunt Script](https://github.com/P0w3rChi3f/start-hunt.ps1)

1. script to search for all files that have a .ZIP or .RAR extension in the C:\Documents\exercise_8 directory
    * 261
2. script to identify which files within the IdentifyDataExfil_ADS directory have an ADS.  
    * 3
3. names of the files that contain the ADS
    * idblcsoznj.txt
    * wfzardupoq.txt
    * pqyuemditc.txt  
4. the last 4 digits of the SHA1 for each file
    * COA4
    * 5332
    * 6919  
5. Extract the ADS into files and use PowerShell to determine the file signature of each file
     file was extracted from ADS1  
     * RAR
6. Content accessable - yes
7. file was extracted from ADS2  
    * Zip
8. content of the file extracted from ADS2  
    * ex8_pwdump.txt
9. type of file was extracted from ADS3  
    * Text
10. content of the file extracted from ADS3
    * Nothing of Value  
11. PowerShell searches to identify the file signature of all the files we have found, including those within an ADS. How many TXT files have a file signature that does not imply it is a text file?  
    * 58  

## Exercise 4.2-07: Identify Keylogger Artifacts on a Windows System

[PowerShell Get-Content Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)  
[APT1 Documentation](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/viewer.html?pdfurl=https%3A%2F%2Fmalware.lu%2Fassets%2Ffiles%2Farticles%2FRAP002_APT1_Technical_backstage.1.0.pdf&clen=1750876&chunk=true)  
[GRR Rapid Response Documentation](https://grr-doc.readthedocs.io/en/latest/)  

1. Where was the currently running keylogger found on the system?
    * `get-item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
    * `Get-CimInstance Win32_Process | Where-Object {$_.name -match "key"} | Select-Object Name, Path`

2. What additional log file was created around the same time as teeamware.log?  
    * `(Get-Content c:\windows\keyX.exe | Select-String -Pattern "teeamware.log" -Context (5,5))`
      * $env:LocalAppdata\keyX.exe
      * $env:appdata\teeamware.log
      * $env:LocalAppdata\microsoft\advkey.log
      * driver.pyt
    * `Compare-Object (Get-ItemProperty $env:APPDATA\teeamware.log).LastWriteTime (Get-ItemProperty $env:LOCALAPPDATA\Microsoft\advkey.log).LastWriteTime -IncludeEqual`

3. Where was the additional log file from Question 2 located on the system?  

4. What is the value name of the entry found in the associated registry run key?
    * Keyboard Driver

## Exercise 4.2-08: Understand a Possible Phishing Attempt

[Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)  
[NetworkMiner](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/viewer.html?pdfurl=https%3A%2F%2Fwww.netresec.com%2Fdocs%2FNetworkMiner_Manual.pdf&clen=230005&chunk=true)  
[QuickStego](http://www.quickcrypto.com/free-steganography-software.html)

1. (DNS) && !(ICMP) - 69.5
   * Statistics, Protocol History
2. smtp - Present
3. smtp - 0.2%
4. smtp.req.comman == "MAIL" - rocketmail
5. smtp.req.comman == "MAIL" - kelly  
6. smtp.req.comman == "MAIL" -> Follow TCP Stream - Press Release
7. smtp.req.comman == "MAIL" -> Follow TCP Stream - internal_discuss.zip
8. smtp.req.comman == "MAIL" -> Follow TCP Stream - Base64
9. False
    * [Carve out Data With WireShark](https://osqa-ask.wireshark.org/questions/61169/extract-an-attachment-from-a-sniffed-smtp-session/)
    * [Base64 Decode binaries with PowerShell/.NET](https://eddiejackson.net/wp/?p=23393)
    * My code
      * extrated the base64 encoded zip file and saved as 'carve.b64'

        ``` PowerShell

          $b64 = get-content .\carve.b64
          $filepath = $env:USERPROFILE\Desktop\Decoded.zip
          $byteArray = [system.conver]::FromBase64string($b64)
          [system.io.file]::WriteAllBytes($filepath, $byteArray)

        ```

    * Alternate Solution
      * Find packet -> Right click  

10. NetworkMinor -> files -> right click internal_discuss.zip -> Calculate - e73a
11. NetworkMinor -> files -> right click internal_discuss.zip -> Calculate - 344
12. NetworkMinor -> files -> right click internal_discuss.zip -> Calculate - 10/09/2018 06:00 Pm
13. NetworkMinor -> files -> right click internal_discuss.zip -> Open - EBC2-Table.bat
14. Host enmumeration
15. Quick Stego -> open Image -> copy the text
16. Windows default tools to base64 decode  
    * `certutil -decode <file with b64 code> data.txt`
    * `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("blahblah"))`

``` Other Notes
* base64 stuff
  [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("nVnV"))
```

## Mod 4 Test Review

1. Given
2. Given
3. Know how to scan the registry key with remote PowerShell use Given IP  (4.1-05)
    * Read in the IOC List

    ```PowerShell
      $KnwIOCs = (get-content .\IOCs.txt | split-path -leaf).replace('"','')
    ```

    * Get the local Registry Artifacts

    ```PowerShell
      $RegItems = @()
      $RegItems += get-item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
      $RegItems += get-item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
    ```

    * Get the Remote Registry Artifacts

    ```PowerShell
      $regItems = Invoke-Command -ComputerName $ip -Credential $creds -ScriptBlock {
        get-item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
        get-item HKCU$:\Software\Microsoft\Windows\CurrentVersion\Run
      }
    ```

    * Code to compare the IOC list to Registry Items

    ```PowerShell
    foreach ($item in $RegItems.property){
      if ($item -in $knwIOCs){
        $item
        }
    }
    ```

4. what binary is associated with IOC in Registry
    * `get-item HKCU$:\Software\Microsoft\Windows\CurrentVersion\Run`
5. What DLL is on system from list - 4.2-07 #2
    * get-process -id 2296 | select -expandproperty Modules | select moduleName, FileName
    * (get-content c:\Windows\hpisnst.exe | select-string -pattern "[A-z]+\.dll").matches.value
6. find mutant of the binary (handle, procmon, GRR)
    * `.\handle64.exe -a | findstr Mutant`
    * `get-ciminstance win32_process | where {$_.name -eq "adobeupdater.exe"} | select Name, TreadCount`  
7. Look for range of files, log files, lateral movement, executed?, IPs, prefetch, strings

    ``` Powershell
    Get—ChildItem —path c:\ —Include log —Recurse —ErrorAction SilentlyContinue —force | Where—object {S_.CreationTime —ge "01/02/2018" —and $_.CreationTime —le "01/04/2018"} | Full name,Creationtime, lastwritetime  
    ```

    Or  

    ```PowerShell
    get-childitem -path path -recurse -force -erroraction silentlycontinue | where-object {$_.CreationTime -gt "time" -and $_.CreationTime -lt "time"} select-object Name, CreationTime
    ```

4.1-04 - Notes up above  
4.2-07 #2  
2.3-09 - Notes made  
8.1-059  
