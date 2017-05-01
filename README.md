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
- Config file specifies minimum size of buffer to search for
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
./binaryfairy [-d] filename
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