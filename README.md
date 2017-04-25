# binaryfairy
Team *I Am Root* CSE545 binary exploit scanning tool:

## Dependencies
python-dev libffi-dev build-essential virtualenvwrapper

## Installation Instructions

```buildoutcfg
sudo aptitude install python-dev libffi-dev build-essential virtualenvwrapper
sudo virtualenv angr
sudo pip install angr
git clone https://github.com/Nkury/cse545-ctftools.git
```

TODO:  Populate Readme

## Tool Requirements:
#### Need to haves:
- Search the binary file for all function calls that allocate a buffer (greater than some specified size)
- Check if one of the specified vulnerable functions is called in that function
- If a vulnerable function call is found print out:
  - Command line switches to command optional outputs
  - Objdump output of vulnerable function
  - Name of function in binary and offset in binary
  - Offset to saved EIP
  - Address of EIP
  - Size of buffer
#### Nice to haves:
- Read config file from ~/ to specify additional "bad" functions
- Config file specifies minimum size of buffer to search for
- Function specific code:  i.e. for strcpy, check if first argument is in .rodata and if so it's not vulnerable, so skip it.
- Generate shellcode to overwrite saved EIP