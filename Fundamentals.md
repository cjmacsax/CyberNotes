
# Linux

## Machine Info

`hostname`
`whoami`
`id`
`uname -a`
`uname -r` (kernel)
`netstat -l` returns listening interfaces

## Apt

`apt-cache` used to provide info about packages installed on the system. `apt-cache search impacket`

Show all installed packages with `apt list –installed`

## FHS

`/bin` binaries
`/boot` static bootloader and kernel executables
`/dev` contains device files to facilitate hardware
`/etc` configuration files
`/home` user subdirectories
`/lib` shared library files
`/media` mount location for USB drives and such
`/mnt` temporary mount point for regular filesystems
`/opt` optional files such as third-party tools
`/root` home directory for root user
`/sbin` contains executables for system administration
`/tmp` temporary directory that is cleared upon system boot
`/usr` contains executables, libraries, etc.
`/var` contains variable data files such as logs, email in-boxes, web server. etc.


## FIND

`find [location] [options]`
	`-type [type]`
	`-name [name]`
	`-user [user]` filters files for a specific user
	`-exec [command] {} \;`
	`2>/dev/null` redirects STDERR (gets rid of "permission denied")
	`-newermt 2020-03-03` only shows files newer than that date
	`-size +20k` larger than 20 kilobytes

## Permissions

Permission assignment:
	- r = 4
	- w = 2
	- x = 1
	- So, 764= `rwxrw-r--`
	- order: Owner, Group, Others

`chmod`
`chown [user]:[group] [file]`  


SUID and GUID
	Set user ID and Set group ID
	`rws` instead of `x` 



## User Management
`useradd`
`userdel`
`usermod`
`addgroup`
`delgroup`
`passwd`


## Redirection/Piping

STDIN - 0
STDOUT - 1
STDERR - 2

Redirection
	`2> stderr.txt`
	`1> stdout.txt`
	`>>` appends, as in: 
		`find /etc/ -name passwd >> stdout.txt` this redirects the `find` output to a file
	`|` is used to pipe from one program to another as in:
		 `find /etc/ -name *.conf 2>/dev/null | grep systemd | wc -l` this will find data, and then use that output with a `grep` and then count words


Grep
	- `cat /etc/passwd | grep "/bin/bash"`
	- `-i` ignore case
	- `-r` recursive
	- `-n` print line numbers
	- Using `-v` will exclude certain options:
		`cat /etc/passwd | grep -v "false\nologin"` 
	- Cut: `-d` specifies the character to set the delimiter to, and `-f` specifies the position in the line we want to output
		`cat /etc/passwd | grep -v "false\nologin | cut -d":" -f1`
	- Replace: `tr`
		`cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "` replaces colons with spaces
	- Column: `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t`
	- Use `sort` to automatically sort results as well

## Execute Multiple Commands

`;`, `&&`, and `|`
- `;` executes them all separately as if you entered them all as commands one at a time
- `&&` will only execute the next command if the previous was successful
- `|` uses the return from the previous command as input for the next

## REGEX

Regular Expressions

`()` define group parts of a regex. patterns that should be processed together

`[]` define character classes, a list of characters to search for such as `[a-z]`

`{}` define quantifiers. specify a number or range, which will indicate how many times a previous pattern should be repeated.

`|` OR operator, shows results when one of the two expressions matches. `(true|false)` 

`.*` AND operator. displays results when both expressions match.




## System Logs

- Kernel logs `/var/log/kern.log`
- System logs `/var/log/syslog`
- Authentication `/var/log/auth.log`
- Applications `/var/log/[app]/[log]


## Command Shortcuts

- `ctrl + A` move cursor to beginning of line
- `ctrl + E` move cursor to end of line
- `ctrl + <- or ->` move cursor to beginning or end of a word
- `ctrl B/F` jump backward/forward one word
- `ctrl + L` clear terminal
- `ctrl + R` view command history (arrow keys to select through them)
## Processes

Daemons are denoted with a `d` at the end of the name, such as `systemd`

`systemctl`
- `start`
- `status`
- `enable`
- `list-units –type=service`

Use `journalctl` to view logs about a service to view errors

`ps -aux | grep [name]`

`kill`
- `-l` to list all signal options
- Most common are 1,2,3,9,15,19,20
- `kill 9 [pid]`

`jobs` to view background processes
- Use `&` at the end to automatically background
- `openvpn [file] &`
- `fg [#]` to foreground

## TCPDUMP

`tcpdump`
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

# Windows

## Machine Info

`Get-WmiObject -Class win32_OperatingSystem` OS info
- `Win32_Process` process list
- `Win32_Service` list of services

## File Structure

`C:\` root directory
- `Program Files`: Whatever programs match the system type (64-bit systems will store 64-bit files. 32-bit stores 16 and 32 bit programs.)
- `Program Files (x86)`: on 64-bit systems, this is where 32 and 16-bit programs are installed
- `ProgramData`: hidden folder containing data for programs
- `Users`: profiles for each user
- `Default`: default profile template for all users
- `Public`: shared files between all users


## Permissions

Full Control: Allows read, write, changing, delete
Modify: allows read, write, delete
List Folder Contents: Allows viewing and executing
Read and Execute
Write: Allows for adding files to folders and writing for files
Read: allows for viewing and listing
Traverse: move through folders, but not necessary list

`icacls`
`get-executionpolicy -list`

## CMD

`set` - check environment path and other system variables
`ver` - check OS version
`systeminfo`
`help [command]` or `[command] -h`
`cls` clear shell
`ipconfig /all`
`del [file]` delete

`more`
- displays longer files in page view
- `more [file]`
- `systeminfo | more` for commands that return a lot of text

`dir  /a` hidden files
`dir /s` current directory and all subdirectories

## Powershell

`Find-Module -Name "PowerShell*"
- locates modules of that name from common repositories
### Enumerate

`Get-LocalUser`
	`Get-LocalUser | WhereObject -property PasswordRequired -Match False`
`Get-LocalGroup`
`get-process`
`get-service`
`Get-NetTCPConnection`
`new-item`, `remove-item`, `copy-item`
### Files
`get-content` (same as `type`)
`get-childitem` similar to `dir` or `ls`
- Powershell "find" command: `Get-ChildItem -Path C:\ -Recurse -Filter *flag*`
`set-location` is the same as `cd`
``

### Help
`get-command` grabs all cmdlets installed
	`get-command New-*` returns all cmdlets that are `new-[something]`
`get-help [cmdlet]` displays info about a cmdlet
	`get-help get-command` to get help about `get-command`
	`-examples` will show you use scenarios
`get-alias` shows alternate command options
- `get-alias type` will return `get-content`
`[Object] | Get-Member` shows properties

### Operators
- example `Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"`
	- filters a list of files where the property extension is equal (operator) to .txt 
- `-eq` equal to
- `-ne` not equal
- `-gt` greater than
- `-ge` greater than or equal to
- `-lt` less than
- `-le` less than or equal to
- `-like` matches a string pattern (`Where-Object -Property "Name" -like "ship*"`)
### File Hash
`Get-FileHash '[location]' -Algorithm [hash type]`


## Services and Processes

`tasklist` processes

`netstat -abon`
- `-a` all active TCP connections and TCP/UDP listeners
- `-b` displays executables associated with active connections
- `-n` same as `-a` but no DNS resolution
- `-o` reveals PID of connections

`Get-Service`

`Get-ACL -Path [executable path] | Format-List`
- examine service permissions

`sc` configure and manage services
- `sc qc` queries a service
- you can specify hostnames or ip for devices on network with `sc //[host or ip]`

SysInternalTools `\\live.sysinternals.com\tools\[tool]`
- allows you to administer windows systems without installing anything
- Some tools: process explorer, task manager, process monitor, TCPView, PSExec

Task Manager
- `taskmgr` in CMD or PowerShell

To see process binary paths: `get-process | select-object processname,path | fl`