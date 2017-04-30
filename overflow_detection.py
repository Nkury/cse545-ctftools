#!/usr/bin/python2

import os
import sys
import angr
import re

project = angr.Project(sys.argv[1])

#let's find the buffer overflow (overwriting the return address)
#overwriting the return pointer with user-controllable data will generate
#an "unconstrained" state: the symbolic executor does not know how to proceed
#since the instruction pointer can assume any value

#by default angr discards unconstrained paths, so we need to specify the
#save_unconstrained option
print "finding the buffer overflow..."
pg = project.factory.path_group(save_unconstrained=True)

#symbolically execute the binary until an unconstrained path is reached
while len(pg.unconstrained) == 0:
    pg.step()

unconstrained_path = pg.unconstrained[0]
crashing_input = unconstrained_path.state.posix.dumps(0)
#cat crash_input.bin | ./CADET_00001.adapted will segfault
#unconstrained_path.state.posix.dump(0,"crash_input.bin")
print "buffer overflow found!"
print repr(crashing_input)
