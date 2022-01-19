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

* Scenario 3  
  * Q1 - Using the map and based on the COA 1 in the attack diagram provided by the CTE squad, what is the best sensor placement position, if your team only has two network sensors? Why?

  ```notes

  ```

  * Q2 - Using the same resources, what is the best sensor placement position if your team only has one network sensor? Why?  

  ```notes

  ```

  * Q3 - Using the same resources, what is the best sensor placement position, if your team only has one network sensor and two host sensors? Why?

  ```notes

  ```
