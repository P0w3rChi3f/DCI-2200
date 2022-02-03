# Module 4: Secure Stage Operations  

## Exercise 4.1-01: Investigate a False Positive

[Symantec Indicators of Compromise](.\Documents\SymantecIndicatorsofCompromise.pdf)  

* Chrome x86 hash values  
  * `https://strontic.github.io/xcyclopedia/library/chrome.exe-9586D6F3312D6A78A743DC51C67C3A7F.html`  

## Exercise 4.1-02: Investigate a True Positive

* Static way of finding the IP
  * `strings64.exe .\ituneshelper.exe | -pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?"`

  * `(get-content <path/to/file/including/binarys> | select-string -pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?").Matches.Value`  

* Evidence of network traffic from ituneshelper Running malware
  * `netstat -naob | select-string "Ituneshelper" -context (1,0)`

  * `get-netTCPConnecton | select LocalAddress, LocalPort, RemoteAddress, RemotePort, state, {name="Process; expression={($_.OwningProcess | foreach {get-process -id $_}).ProcessName}} | select-string -pattern "ituneshelper"`
