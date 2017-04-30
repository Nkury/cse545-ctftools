#!/usr/bin/python2

import os
import sys
import angr
import re
import archinfo

#import overflow_detection

# Global "bad" function array
# TODO: pull from config file
unsafe_functions = ["strcpy", "strcat", "gets", "fgets", "puts", "fputs", "strlen", "strcmp"]

class vulnFunc:
    def __init__(self):
        self.name = ""
        self.addr = 0x0
        self.unsafeFuncList = []
        self.unsafeFuncAddrList = []
        self.disassembly = ""

    def clear(self):
        self.name = ""
        self.addr = 0x0
        self.unsafeFuncList = []
        self.unsafeFuncAddrList = []
        self.disassembly = ""

# Error usage function
def usage():
    print("Usage: " + __file__ + " <path to binary file>")
    print("\tExample: " + __file__ + " ./test.bin")

def openProj(filename):
    # Open file for parsing
    proj = angr.Project(filename, load_options={'auto_load_libs': False})

    print("Binary Name: " + proj.filename)
    print("Binary Arch: " + str(proj.arch))
    print("Binary Entry: " + str(proj.entry))
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
    for unsafeFunc in unsafe_functions:
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

                            # if vulnFunc object for vulnFuncName already in array, point vFunc to it
                            # and update the unsafeFuncList and unsafeFuncListAddr arrays
                            if any(f.name == vulnFuncName for f in vulnFuncs):
                                for index, f in enumerate(vulnFuncs):
                                    if f.name == vulnFuncName:
                                        vulnFuncIndex = index
                                        vFunc = vulnFuncs[vulnFuncIndex]
                                        vFunc.unsafeFuncList.append(unsafeFunc)
                                        vFunc.unsafeFuncAddrList.append(vulnFunc_node.addr)
                            else:
                                # Create new vulnFunc instance to be populated and appended
                                vFunc = vulnFunc()

                                # Update the name and address fields for that vulnerable function
                                vFunc.name = vulnFuncName
                                vFunc.addr = vulnFuncAddr
                                vFunc.unsafeFuncList.append(unsafeFunc)
                                vFunc.unsafeFuncAddrList.append(vulnFunc_node.addr)

                                vulnFuncs.append(vFunc)

    return vulnFuncs

def locateBuffers(vulnFunc, arch):
    # Chop up the disassembly so we can parse it line by line
    disasm = vulnFunc.disassembly.splitlines(True)

    # Figure out what ebp will be called in the disassembly
    if arch.name == archinfo.ArchAMD64.name:
        ebp = "%rbp"
    elif arch.name == archinfo.ArchX86.name:
        ebp = "%ebp"
    else:
        sys.exit("Unsupported architecture")

    # Loop through the disassembly code and search for reference to %ebp-value
    # If we see %ebp-value before a call to an unsafe function, there may be a
    # buffer overflow vulnerability
    for lines in disasm:
        match = re.search('^\s*(\w+?):\s*?\w*?\s*(.+?)$', lines)

        if match:
            print(match.group(1) + " " + match.group(2))
        else:
            print("Match failed:\n" + lines)



def disassembleBinary(filename):
    objdump = os.popen('objdump -dC --no-show-raw-insn ' + sys.argv[1]).read()
    return objdump

def parseDisassembly(objdump, vulnFuncs):
    for vFunc in vulnFuncs:
        startIndex = objdump.find(str(format(vFunc.addr, 'x')) + ":")
        substr = objdump[startIndex-2:]
        endIndex = substr.find("\n\n")
        vFunc.disassembly = substr[:endIndex]
    return vulnFuncs

# Main
if(len(sys.argv) != 2):
    usage()
    exit(-1)

proj = openProj(sys.argv[1])

# Generate CFG
cfg = generateCFG(proj)

# Locate all functions that call vulnerable function
# vulnFuncs is a dictionary with key = <name> and value = <entry point>
vulnFuncs = locateVulnerableFunctions(cfg)

# Disassemble binary
# objdump is the output of running objdump
objdump = disassembleBinary(sys.argv[1])

# Chop up disassembly to only include vulnerable functions
# dissFuncs is a dictionary with key = <name> and value = <objdump for function>
dissFuncs = parseDisassembly(objdump, vulnFuncs)

for vFunc in vulnFuncs:
    print("\n~Hey, Listen!!~ " + vFunc.name + "(" + str(format(vFunc.addr, 'x')) + ") calls:")

    for index, func in enumerate(vFunc.unsafeFuncList):
        print(str(func) + " at address 0x" + str(format(vFunc.unsafeFuncAddrList[index], 'x')))

    # print("Disassembly of " + vFunc.name + ":")
    # print(vFunc.disassembly)

    locateBuffers(vFunc, proj.arch)

