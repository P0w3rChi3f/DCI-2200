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

  * `get-netTCPConnecton | select LocalAddress, LocalPort, RemoteAddress, RemotePort, state, {name="Process; expression={($_.OwningProcess | foreach {get-process -id $_}).ProcessName}} | select-string -pattern "ituneshelper"`

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

[Scripts](https://github.com/P0w3rChi3f/Get-Baselines/blob/main/Get-DCIBaseline.ps1)

## Exercise 4.2-06: Identify Data Exfiltration Artifacts on a Windows System

[List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)  
[Alternate Data Streams in NTFS (PowerShell)](https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs)  
[PowerShell Check File Headers](http://learningpcs.blogspot.com/2012/07/powershell-v3-check-file-headers.html)  
[PowerShell Get-Content Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)  
[Get Hex Dumps of Files in PowerShell](https://www.itprotoday.com/powershell/get-hex-dumps-files-powershell)  

[Started my Hunt Script](https://github.com/P0w3rChi3f/start-hunt.ps1)