
## About
- Tool for malware detection by identifying matching patterns in files, memory, or other data
- Identifies binary and textual patterns such as hexadecimal and strings
- Yara rules are used to label patterns

## Usage
- `yara [rules.yar] [argument]`
	- `argument` can be a file, directory, or process ID

## Writing Rules
- https://yara.readthedocs.io/en/stable/writingrules.html

```yara
rule dummy #declare rule
{
	strings:
		$hello_world = "Hello World!"
		$hello_world_lowercase = "hello world"
		$hello_world_uppercase - "hello world"
		
	condition:
		any of them
}
```

- `strings` checks for strings
- Every rule needs a `condition` which can be:
	- boolean value `true/false`
	- the name of the string
	- `any of them`
	- comparison operators `<= >= !=` which will return based on the count of string occurences
	- multiple arguments `$hello_world and filesize < 10KB`

## Yara Tools

https://github.com/InQuest/awesome-yara
### Loki
- open-source Indicator of Compromise (IOC) scanner
- Download https://github.com/Neo23x0/Loki/releases
- README https://github.com/Neo23x0/Loki/blob/master/README.md
- Navigate to `Loki/signature-base` to see what premade yara rules exist for common threats
- `python loki.py -p [malicious_file]`
	- `-p` path to file

### Thor
- IOC and Yara scanner
- Download https://www.nextron-systems.com/thor-lite/

### FENRIR
- https://github.com/Neo23x0/Fenrir
- bash script capable of running similar functions as previous 2 tools

### YAYA
- Yet Another Yara Automation
- helps manage multiple Yara repositories
- imports a set of high-quality YARA rules and then lets researchers add their own rules, disable rules, and run scans of files.
- Only runs on Linux

### yarGen
- generator for YARA rules
- For example. if we run `YARA` on a webshell but it detects nothing, this means we need a new ruleset so it can be detected in the future or on other servers.
- `python3 yarGen.py -m [path] --excludegood -o [path]`
	- `-m` is the malicious file we need to detect
	- `-o` is output for new rule file
	- `--excludegood` force to exclude all goodware strings to avoid false positives
### yarAnalyzer
- creates statistics on a yara rule set and files in a sample directory
- creates a CSV file with information about selected rules

### Valhalla
- https://www.nextron-systems.com/valhalla/
- Can search Yara rules based on keyword, ATT&CK techniques, hash, or rule names.
- 
