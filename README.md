# Team *I Am Root* CTF Suite
CSE545 - Software Security - ASU Fall 2016

Members: gates, a11aakbar, jsymmes22

## Our Tools

### binaryfairy - Binary Vulnerability Analysis Tool

#### Description
Ever wish you had a tool to locate large buffers in binary files?  Well now you can!! With the binaryfairy!!!
When passed an x86 or amd64 linux binary, binaryfairy scans for known unsafe functions and checks if large buffers
are accessed before calling the unsafe function.

Future enhancements:
- Read config file from ~/ to specify additional "bad" functions
- Function specific code:  i.e. for strcpy, check if first argument is in .rodata and if so it's not vulnerable, so skip it.
- Generate shellcode to overwrite saved EIP

#### Dependencies
git python-dev python-pip libffi-dev build-essential virtualenvwrapper
#### Installation Instructions

Navigate to folder where you'd like to install our tools
```
mkdir ~/i_am_root_ctf && cd ~/i_am_root_ctf
```
Run the following commands to download the tools, and install the required dependences
NOTE:  These package names apply to *buntu flavors of Linux.  We tested this on Xubuntu 16.04 x64 [Link to iso file](http://ftp.ussg.iu.edu/linux/xubuntu/16.04/release/xubuntu-16.04.2-desktop-amd64.iso)
```
sudo apt-get install git python-dev python-pip libffi-dev build-essential virtualenvwrapper
git clone https://github.com/Nkury/cse545-ctftools.git
cd cse545-ctftools
sudo virtualenv angr
sudo pip install angr
```
#### Usage
```
binaryfairy.py [-h] [-d] [-b MIN_BUFF_SIZE] filename
```
#### Sample Output
```
$ ./binaryfairy.py sample_c
Binary Name: sample_c
Binary Arch: <Arch AMD64 (LE)>
Binary Entry: 0x400980
~~~Hey, Listen!!! I found a possible vulnerability in read_file!!~~~
0x400fc1: [ebp-0x128] reference before calling fgets(0x401026)
0x400fd7: [ebp-0x128] reference before calling fgets(0x401026)
0x400feb: [ebp-0x118] reference before calling fgets(0x401026)
0x400ff2: [ebp-0x118] reference before calling fgets(0x401026)
0x401010: [ebp-0x118] reference before calling fgets(0x401026)
0x401017: [ebp-0x110] reference before calling fgets(0x401026)
~~~Hey, Listen!!! I found a possible vulnerability in read_note!!~~~
0x400c67: [ebp-0x110] reference before calling strcmp(0x400ce4)
0x400c6e: [ebp-0x124] reference before calling strcmp(0x400ce4)
0x400c9b: [ebp-0x124] reference before calling strcmp(0x400ce4)
0x400cc9: [ebp-0x120] reference before calling strcmp(0x400ce4)
0x400cd0: [ebp-0x120] reference before calling strcmp(0x400ce4)
0x400cd7: [ebp-0x110] reference before calling strcmp(0x400ce4)
```

### shellcoder - The Shellcode Generator

#### Description
A tool that aims to make writing shellcode as easy as ever. Who needs ASCII to HEX converters when you can use shellcoder?! Simply put in the name of the file you would like to open and shellcoder will do the work for you and put the results in a handy file called "shellcode". If no name is provided, it assumes you meant bin/sh. 

Future enhancements:
- Provide filename that the shellcode will be injected in and it will automatically overflow the buffer and overwrite the saved eip register.

#### Usage
```
shellcode <filename>
```

#### Sample Output
```
$ ./shellcoder 
Here is the shellcode to inject: \x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\x66\x90\x90
and it is  144  characters long and  36  bytes long
```
and the file shellcode has:
```
\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\x66\x90\x90
```
which can be fed into an argument for a buffer overflow exploit.

### phpfairy- The php static analysis tool

#### Description
This tool scans a php file for XSS, OS Command Injection, and SQL Injection. It does this by parsing the php file and collecting an array of user controlled variables. Then statements where user controlled variables are checked for sanitization methods. If a user controlled variable is found in a risky place then the user is alerted of the vulnerability line number.

Future enhancements:
- Patches code automatically by sanitizing the user controlled variables in a new file.  

#### Usage
```
phpfairy <filename>
```
#### Sample Output

### manage_ctf - Quick and Dirty Management Tool for iCTF

#### Description
I built off what Connor Nelson sent the class so we can run some basic management commands from an interactive shell

#### Usage
```
manage_ctf [-h] -t TEAM_INTERFACE -u USERNAME -p PASSWORD [-d]
```

#### Sample Output
```
./manaage_ctf -u <username> -p <password> -t <mgmt serer ip>
Please select an option:
1: Get Game Status
2: Get Service List
3: Get Targets
4: Submit Flag
5: Exit

```