#!/usr/bin/python2

import os
import sys
import angr
import re

# Global "bad" function array
# TODO: pull from config file
bad_functions = ["strcpy", "strcat", "gets", "fgets", "puts", "fputs", "strlen"]

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
    # create empty list of vulnerable functions
    vulnFuncs = {}

    # Search CFG for calls to vulnerable functions
    for func in bad_functions:
        # Iterate over functions in CFG
        for key, value in cfg.kb.functions.iteritems():
            # Temporary hack to disregard library references
            if key < 0x01000000:
                # Found call to vulnerable function
                if func == value.name:
                    print("\n~Hey, Listen!! I found a call to " + func + "!~")
                    # Get node for vulnerable function call
                    entry_node = cfg.get_node(key)

                    for node in entry_node.predecessors:
                        # Make sure node has a function name
                        if node.name:
                            try:
                                parsed_node = re.search('^(.+?)\+(.+?)$', node.name)
                                name = parsed_node.group(1)
                                offset = int(parsed_node.group(2), 16)
                                addr = node.addr - offset
                            except AttributeError:
                                name = node.name
                                offset = 0
                                addr = node.addr

                            if name not in vulnFuncs:
                                vulnFuncs[name] = addr

                            print(func + " called from " + name + "(" + str(hex(addr)) + ") at offset " + str(hex(offset)))

    return vulnFuncs

# Main
if(len(sys.argv) != 2):
    usage()
    exit(-1)

# Generate CFG
cfg = generateCFG(sys.argv[1])

locateVulnerableFunctions(cfg)

# Run objdump on file
objdump = os.popen('objdump -d ' + sys.argv[1]).read()
