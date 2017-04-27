#!/usr/bin/python2

import os
import sys
import angr
import pprint

# Global "bad" function array
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

cfg = proj.analyses.CFG()

# print out all function calls in the binary
# print(list(cfg.kb.functions.values()))

# print out
for func in bad_functions:
    for key, value in cfg.kb.functions.iteritems():
        if key < 0x01000000: # temporary hack to disregard library references
            if func == value.name:
                # print("Found call to vulnerable function " + func + " at " + str(hex(value.addr)))
                # print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(key)))
                entry_node = cfg.get_node(key)
                # print("Predecessors of the entry point:", entry_node.predecessors)
                for node in entry_node.predecessors:
                    if node.name:
                        print(func + " called from " + node.name + " at address " + str(hex(node.addr)))
                        # print("Successors of the entry point:", entry_node.successors)

                # print("key = " + str(hex(key)))
                # print("value = " + str(value))

# print(cfg.kb.functions.keys()[cfg.kb.functions.values().index().name])

# pprint.pprint(dict(cfg.kb.functions))
print("~Hey, Listen!!~")
