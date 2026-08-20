import os

with open("cgull/__init__.py", "r") as f:
    lines = f.readlines()

with open("cgull/__init__.py", "w") as f:
    skip = False
    for line in lines:
        if line.startswith("<<<<<<<"):
            skip = True
        elif line.startswith("======="):
            skip = False
            f.write('__version__ = "0.7.0"\n')
        elif line.startswith(">>>>>>>"):
            pass
        elif not skip:
            f.write(line)
