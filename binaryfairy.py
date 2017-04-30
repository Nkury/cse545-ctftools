#!/usr/bin/python2

import os
import sys
import angr
import re
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

# Generate CFG for the binary and return it
def generateCFG(filename):
    # Open file for parsing
    proj = angr.Project(filename, load_options={'auto_load_libs': False})

    print("Binary Name: " + proj.filename)
    print("Binary Arch: " + str(proj.arch))
    print("Binary Entry: " + str(proj.entry))

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
    # vFunc = vulnFunc()

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

    print("\nPrinting Current vulnFunc Array")
    for i, f in enumerate(vulnFuncs):
        print("vFunc[" + str(i) + "].name: " + f.name)
        print("vFunc[" + str(i) + "].addr: 0x" + str(format(f.addr, 'x')))
        for j, u in enumerate(f.unsafeFuncList):
            print("vFunc[" + str(i) + "].unsafeFuncList[" + str(j) + "]: " + u)
            print("vFunc[" + str(i) + "].unsafeFuncAddrList[" + str(j) + "]: 0x" + str(format(f.unsafeFuncAddrList[j], 'x')))
    print("done\n")

    return vulnFuncs

def disssembleBinary(filename):
    objdump = os.popen('objdump -d ' + sys.argv[1]).read()
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

# Generate CFG
cfg = generateCFG(sys.argv[1])

# Locate all functions that call vulnerable function
# vulnFuncs is a dictionary with key = <name> and value = <entry point>
vulnFuncs = locateVulnerableFunctions(cfg)

# Disassemble binary
# objdump is the output of running objdump
objdump = disssembleBinary(sys.argv[1])

# Chop up disassembly to only include vulnerable functions
# dissFuncs is a dictionary with key = <name> and value = <objdump for function>
dissFuncs = parseDisassembly(objdump, vulnFuncs)

for vFunc in vulnFuncs:
    print("\n~Hey, Listen!! " + vFunc.name + "(" + str(format(vFunc.addr, 'x')) + ") calls:\n")

    for index, func in enumerate(vFunc.unsafeFuncList):
        print(str(func) + " at address 0x" + str(format(vFunc.unsafeFuncAddrList[index], 'x')))

    print(vFunc.disassembly)

