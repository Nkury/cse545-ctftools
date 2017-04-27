#!/usr/bin/python2

import os
import sys
import angr
import pprint

# Global "bad" function array
# TODO: pull from config file
bad_functions = ["strcpy", "strcat", "gets", "fgets", "puts", "fputs", "strlen"]

# Error usage function
def usage():
    print("Usage: " + __file__ + " <path to binary file>")
    print("\tExample: " + __file__ + " ./test.bin")

# Main
if(len(sys.argv) != 2):
    usage()
    exit(-1)

# Open file for parsing
proj = angr.Project(sys.argv[1], load_options={'auto_load_libs': False})

print("Binary Name: " + proj.filename)
print("Binary Arch: " + str(proj.arch))
print("Binary Entry: " + str(proj.entry))

# Generate control flow graph for binary
cfg = proj.analyses.CFG()

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
                    if node.name:
                        print(func + " called from " + node.name + " at address " + str(hex(node.addr)))


