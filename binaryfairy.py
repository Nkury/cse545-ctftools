#!/usr/bin/python2

import sys

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

print("~Hey, Listen!!~")
