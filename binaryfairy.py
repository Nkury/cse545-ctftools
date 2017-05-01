#!/usr/bin/python2

import os
import sys
import angr
import re
import archinfo
import argparse

# Global "unsafe" function array
# TODO: pull from config file
unsafeFunctions = ["strcpy", "strcat", "strrok", "gets", "fgets", "strlen", "strcmp"]
minBuffSize = 0x100
printDisassembly = False

class vulnFunc:
    def __init__(self):
        self.name = ""
        self.addr = 0x0
        self.unsafeFuncList = []
        self.unsafeFuncAddrList = []
        self.bufferOffsetList = []
        self.bufferAddrList = []
        self.disassembly = ""

    def clear(self):
        self.name = ""
        self.addr = 0x0
        self.unsafeFuncList = []
        self.unsafeFuncAddrList = []
        self.bufferOffsetList = []
        self.bufferAddrList = []
        self.disassembly = ""

# Error usage function
def usage():
    print("Usage: " + __file__ + " <path to binary file> [-d]")
    print("\tExample: " + __file__ + " ./test.bin")

def openProj(filename):
    # Open file for parsing
    proj = angr.Project(filename, load_options={'auto_load_libs': False})

    print("Binary Name: " + proj.filename)
    print("Binary Arch: " + str(proj.arch))
    print("Binary Entry: 0x" + str(format(proj.entry, 'x')))
    return proj

# Generate CFG for the binary and return it
def generateCFG(proj):
    # Generate control flow graph for binary
    cfg = proj.analyses.CFG()
    return cfg

# Search through CFG and find names and entry points for all
# functions that call one of the vulnerable functions
def locateVulnerableFunctions(cfg):
    # create empty list of vulnFunc objects
    vulnFuncs = []
    vulnFuncIndex = 0
    vulnFuncName = ""
    vulnFuncAddr = 0x0

    # Search CFG for calls to unsafe functions
    for unsafeFunc in unsafeFunctions:
        # Iterate over functions in CFG
        for funcAddr, func in cfg.kb.functions.iteritems():
            # Temporary hack to disregard library references
            if funcAddr < 0x01000000:
                # Found call to unsafe function
                if unsafeFunc == func.name:
                    # Get node for vulnerable function call
                    unsafeFunc_node = cfg.get_node(funcAddr)

                    for vulnFunc_node in unsafeFunc_node.successors:
                        # Make sure node has a function name
                        if vulnFunc_node.name and vulnFunc_node.addr < 0x01000000:
                            # Some node.names have hex offsets applied to them
                            # these need to be pulled out before we can use them
                            try:
                                parsedVulnFunc_node = re.search('^(.+?)\+(.+?)$', vulnFunc_node.name)
                                vulnFuncName = parsedVulnFunc_node.group(1)
                                vulnFuncAddr = vulnFunc_node.addr - int(parsedVulnFunc_node.group(2), 16)
                            except AttributeError:
                                vulnFuncName = vulnFunc_node.name
                                vulnFuncAddr = vulnFunc_node.addr

                            # if vule:nFunc object for vulnFuncName already in array, point vFunc to it
                            # and update the unsafeFuncList and unsafeFuncListAddr arrays
                            if any(f.name == vulnFuncName for f in vulnFuncs):
                                for index, f in enumerate(vulnFuncs):
                                    if f.name == vulnFuncName:
                                        vulnFuncIndex = index
                                        vFunc = vulnFuncs[vulnFuncIndex]
                                        vFunc.unsafeFuncList.append(unsafeFunc)
                                        vFunc.unsafeFuncAddrList.append(0) # Invalid for now, but will populate later in code
                            else:
                                # Create new vulnFunc instance to be populated and appended
                                vFunc = vulnFunc()

                                # Update the name and address fields for that vulnerable function
                                vFunc.name = vulnFuncName
                                vFunc.addr = vulnFuncAddr
                                vFunc.unsafeFuncList.append(unsafeFunc)
                                vFunc.unsafeFuncAddrList.append(0) # Invalid for now, but will populate later in code

                                vulnFuncs.append(vFunc)

    return vulnFuncs

def locateBuffers(vulnFunc, arch):
    # Chop up the disassembly so we can parse it line by line
    disasm = vulnFunc.disassembly.splitlines(True)

    print(arch.name)

    # Figure out what ebp will be called in the disassembly
    if arch.name == archinfo.ArchAMD64.name:
        ebp = "%rbp"
    elif arch.name == archinfo.ArchX86.name:
        ebp = "%ebp"
    else:
        sys.exit("Unsupported architecture")

    # Create regex string to match:
    # ebp - some value
    searchString = "^\s*?(\w+?):(?:(?:.*?-(0x\w+?)\(" + ebp + "\).*?)"

    # vulnFunc.unsafeFuncList[] entries
    for funcs in vulnFunc.unsafeFuncList:
        searchString += "|(?:.*?<(" + funcs + ")@plt>)"

    # must add trailing ')' to match the beginning one
    searchString += ")$"

    # print("searchString: " + searchString)

    # compile regex pattern to match when looping through the lines
    pattern = re.compile(searchString)

    currentAddress = 0x0
    unsafeFuncAddrIndex = 0
    foundBuffer = False

    # Loop through the disassembly code and search for reference to %ebp-value
    # If we see %ebp-value before a call to an unsafe function, there may be a
    # buffer overflow vulnerability
    for index, lines in enumerate(disasm):
        m = pattern.match(lines)

        if m:
            for groupNum, g in enumerate(m.groups()):
                if g:
                    # Store the current address
                    if groupNum == 0:
                        currentAddress = int(g, 16)
                    # Store the buffer address and offset
                    elif groupNum == 1:
                        offset = int(g, 16)
                        # Check if the buffer is large enough
                        if offset >= minBuffSize:
                            foundBuffer = True
                            vulnFunc.bufferAddrList.append(currentAddress)
                            vulnFunc.bufferOffsetList.append(offset)
                    # Store the address of the unsafe function call
                    else:
                        vulnFunc.unsafeFuncAddrList[unsafeFuncAddrIndex] = currentAddress
                        unsafeFuncAddrIndex += 1

    return foundBuffer

def disassembleBinary(filename):
    objdump = os.popen('objdump -dC --no-show-raw-insn ' + filename).read()
    return objdump

def parseDisassembly(objdump, vulnFuncs):
    for vFunc in vulnFuncs:
        startIndex = objdump.find(str(format(vFunc.addr, 'x')) + ":")
        substr = objdump[startIndex-2:]
        endIndex = substr.find("\n\n")
        vFunc.disassembly = substr[:endIndex]
    return vulnFuncs

# Main
parser = argparse.ArgumentParser(description="Search binary files for vulnerable functions")
parser.add_argument("filename", type=str, help="binary to be searched")
parser.add_argument("-d", "--disassemble", action="store_true",
                    help="Disassemble vulnerable functions and print the assembly code")
parser.add_argument("-b", "--min_buff_size", type=str,
                    help="Specify the minimum size of the buffer to search for")

args = parser.parse_args()

if args.disassemble:
    printDisassembly = True

if args.min_buff_size:
    minBuffSize = int(args.min_buff_size, 16)

proj = openProj(args.filename)

# Generate CFG
cfg = generateCFG(proj)

# Locate all functions that call vulnerable function
# vulnFuncs is a dictionary with key = <name> and value = <entry point>
vulnFuncs = locateVulnerableFunctions(cfg)

# Disassemble binary
# objdump is the output of running objdump
objdump = disassembleBinary(args.filename)

# Chop up disassembly to only include vulnerable functions
# dissFuncs is a dictionary with key = <name> and value = <objdump for function>
dissFuncs = parseDisassembly(objdump, vulnFuncs)

for vFunc in vulnFuncs:
    foundPossibleVuln = False
    firstVuln = True

    # If we found buffers of sufficient size:
    if locateBuffers(vFunc, proj.arch):

        for i, unsafeFuncAddr in enumerate(vFunc.unsafeFuncAddrList):
            for j, buffAddr in enumerate(vFunc.bufferAddrList):

                if buffAddr < unsafeFuncAddr:

                    if firstVuln == True:
                        print("~~~Hey, Listen!!! I found a possible vulnerability in " + vFunc.name + "!!~~~")
                        firstVuln = False

                    foundPossibleVuln = True
                    print("0x" + str(format(buffAddr, 'x')) + ": [ebp-0x" + str(format(vFunc.bufferOffsetList[j], 'x')) + "] reference before calling " + vFunc.unsafeFuncList[i] + "(0x" + str(format(unsafeFuncAddr, 'x')) + ")")

        if foundPossibleVuln and printDisassembly:
            print("Disassembly of " + vFunc.name + ":")
            print(vFunc.disassembly)