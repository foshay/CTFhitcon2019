#!/usr/bin/env python
#Wrtiten by @yeongjin
charset = '0123456789abcdef'

def check(name):
    for c in name:
        if not c in charset:
            return False
    return True

import glob
import os

g = list(glob.glob("/bin/*"))

for i in g:
    name = os.path.basename(i)
    if check(name):
        print(name)

g = list(glob.glob("/usr/bin/*"))

for i in g:
    name = os.path.basename(i)
    if check(name):
        print(name)
