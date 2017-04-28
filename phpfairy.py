import sys
import re

def usage():
    print("Usage: " + __file__ + " <path to php file>")
    print("\tExample: " + __file__ + " ./test.bin")
debug = True
if(debug):
    file = "test.php"
else:
    file = sys.argv[1]

if(len(sys.argv) != 2 and not debug):
    usage()
    exit(-1)

req = ("GET[", "POST[")
lineNum = 0
UCvars = []
for line in open(file):
    if any(s in line for s in req) and '=' in line:
        start = line.find('\$') + 1
        end = line.find(' ', start)
        UCvars.append(line[start:end])
    if any(s in line for s in UCvars) and 'mysql_query' in line:
        warn = "Hey! Listen! Possible SQL injection at line " + str(lineNum) + ":"
        print(warn)
        print(line)
    if any(s in line for s in UCvars) and 'echo' in line:
        warn = "Hey! Listen! Possible XSS at line " + str(lineNum) + ":"
        print(warn)
        print(line)
    lineNum = lineNum + 1


print("Hey! Listen! These Variables are user controled!!!")
print(UCvars)




