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
  * (tcp.flags.syn == 1) && !(tcp.flags.ack == 1) && (ip.dst == 204.16.139.24)

* Ended up starting by looking for URL IOCs
  * `tcpdump -nnvXS -r ./beacons.pcapng | grep -nof ./URL.txt`
    * kayauto.net
    * gobroadreach.com

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
