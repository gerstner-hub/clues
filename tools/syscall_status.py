#!/usr/bin/python3

import os
import subprocess
import sys
from pathlib import Path

basedir = Path(os.path.dirname(os.path.dirname(__file__)))
clues = basedir / "install" / "bin" / "clues"

if not clues.exists():
    print("Missing clues binary at", clues, file=sys.stderr)
    sys.exit(1)

syscall_lines = subprocess.check_output([clues, "--list-syscalls"]).splitlines()
num_syscalls = len(syscall_lines)
covered_syscalls = 0

with open(basedir / "src" / "SystemCall.cxx") as code_fd:
    in_create_syscall = False
    for line in code_fd.readlines():
        line = line.strip()
        if in_create_syscall:
            if line == "}":
                in_create_syscall = False
            elif line.find("SystemCallNr::") != -1:
                covered_syscalls += 1
        elif line.find("create_syscall(const SystemCallNr") != -1:
            in_create_syscall = True

print(f"Currently {covered_syscalls} of {num_syscalls} are supported by libclues")
