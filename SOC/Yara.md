
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
- 