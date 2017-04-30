#!/usr/bin/python2

import os
import sys
import angr
import re
#import overflow_detection

# Global "bad" function array
# TODO: pull from config file
bad_functions = ["strcpy", "strcat", "gets", "fgets", "puts", "fputs", "strlen"]

class vulnFunc:
    def __init__(self):
        self.name = ""
        self.addr = 0x0
        self.func = ""
        self.funcAddr = 0x0
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
    # create empty dictionary of vulnerable functions
    vulnFuncs = []

    # Search CFG for calls to vulnerable functions
    for func in bad_functions:
        # Iterate over functions in CFG
        for key, value in cfg.kb.functions.iteritems():
            # Temporary hack to disregard library references
            if key < 0x01000000:
                # Found call to vulnerable function
                if func == value.name:
                    # Get node for vulnerable function call
                    entry_node = cfg.get_node(key)

                    for node in entry_node.successors:
                        vFunc = vulnFunc()
                        # Make sure node has a function name
                        if node.name and node.addr < 0x01000000:
                            try:
                                parsed_node = re.search('^(.+?)\+(.+?)$', node.name)
                                vFunc.name = parsed_node.group(1)
                                vFunc.addr = node.addr - int(parsed_node.group(2), 16)
                                vFunc.func = func
                                vFunc.funcAddr = node.addr
                            except AttributeError:
                                vFunc.name = node.name
                                vFunc.addr = node.addr
                                vFunc.func = func
                                vFunc.funcAddr = node.addr

                            if vFunc.name not in vulnFuncs:
                                vulnFuncs.append(vFunc)

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
    print("\n~Hey, Listen!! " + vFunc.name + " calls " + vFunc.func + " at address 0x" + str(format(vFunc.funcAddr, 'x')) + "!~")
    print(vFunc.disassembly)

