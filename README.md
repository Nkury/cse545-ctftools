# binaryfairy
Team *I Am Root* CSE545 binary exploit scanning tool:

## Dependencies
python-dev libffi-dev build-essential virtualenvwrapper

## Installation Instructions

Navigate to folder where you'd like to install our tools
```buildoutcfg
mkdir ~/i_am_root_ctf && cd ~/i_am_root_ctf

```
Run the following commands to download the tools, and install the required dependences
NOTE:  These package names apply to *buntu flavors of Linux.  We tested this on Xubuntu 16.04 x64 [Link to iso file](http://ftp.ussg.iu.edu/linux/xubuntu/16.04/release/xubuntu-16.04.2-desktop-amd64.iso)
```buildoutcfg
sudo aptitude install git python-dev libffi-dev build-essential virtualenvwrapper
git clone https://github.com/Nkury/cse545-ctftools.git
sudo virtualenv angr
sudo pip install angr
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