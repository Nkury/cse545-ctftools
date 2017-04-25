#!/usr/bin/python2

import os
import sys
import angr

# Global "bad" function array
bad_functions = ["strcpy", "strcat", "gets", "puts"]

# Error usage function
def usage():
    print("Usage: " + __file__ + " <path to binary file>")
    print("\tExample: " + __file__ + " ./test.bin")

# Main
if(len(sys.argv) != 2):
    usage()
    exit(-1)

print("Parsing " + sys.argv[1])

# Open file for parsing
#load_options = {'auto_load_libs': False}
proj = angr.Project(sys.argv[1])

print("Binary Name: " + proj.filename)
print("Binary Arch: " + str(proj.arch))
print("Binary Entry: " + str(proj.entry))

cfg = proj.analyses.CFG()

print("~Hey, Listen!!~")
