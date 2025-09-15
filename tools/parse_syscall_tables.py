#!/usr/bin/python3

# This script parses .tbl files from the Linux kernel source tree and can
# generated C++ headers providing enums for the various architectures and ABIs
# we might encounter while tracing.
#
# For the start this will concentrate on the three PC ABIs: i386, x86_64 and
# x32. The .tbl files are a bit different for each architecture and their
# interpretation is not fully clear to me yet for all variants. I'll try to
# evolve this as I go.

import argparse
import copy
import os
import sys
from dataclasses import dataclass


def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    try:
        fail = kwargs.pop('fail')
    except KeyError:
        fail = False

    print(*args, **kwargs)
    if fail:
        sys.exit(1)


@dataclass
class TableEntry:
    nr: int
    abi: str
    name: str
    entry: str
    compat_entry: str = None
    noreturn: bool = False


class TableParser:

    # keeping architecture and ABI apart is quite difficult here due to the
    # naming scheme and different approaches used between architectures.
    #
    # the architecture keys here relate to the combination of arch
    # sub-directory and syscall .tbl suffix, if any.
    #
    # each syscall .tbl might contain multiple ABIs, depending on the arch.
    ARCH_TABLE_PATHS = {
        #"arm":      "arch/arm/tools/syscall.tbl",
        #"powerpc":  "arch/powerpc/kernel/syscalls/syscall.tbl",
        #"arm64-32": "arch/arm64/tools/syscall_32.tbl",
        #"arm64-64": "arch/arm64/tools/syscall_64.tbl",
        # this contains i386
        "x86-32":   "arch/x86/entry/syscalls/syscall_32.tbl",
        # this contains x86_64 / x64 and x32
        "x86-64":   "arch/x86/entry/syscalls/syscall_64.tbl",
    }

    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--kernel-root",
                                 default="/usr/src/linux", help="where to look for .tbl files to parse")
        self.parser.add_argument("--archs", nargs="*",
                                 help="Architectures which should be processed",
                                 default=self.ARCH_TABLE_PATHS.keys())
        self.parser.add_argument("--list-archs", action='store_true',
                                 help="list valid arguments for --archs")
        self.parser.add_argument("--list-raw", action='store_true',
                                 help="list raw content parsed from .tbl files")
        self.parser.add_argument("--list-abis", action='store_true',
                                 help="list expanded ABI information after processing .tbl files")
        self.parser.add_argument("--list-all-syscalls", action='store_true',
                                 help="list every distinct system call and the ABIs they're found in")
        self.parser.add_argument("--list-unique", action='store_true',
                                 help="list system calls that are unique for each ABI")
        self.parser.add_argument("--show-diff", metavar="ABI1:ABI2",
                                 help="Show differences between the given ABIs")

        # all parsed systems call in the following structure:
        # "arch" → "abi" → [list of TableEntry]
        self.syscalls = {}
        # transformed data in a dictionary of the following structure:
        # "abi" → [list of TableEntry]
        # where certain peculiarities of architectures are leveled, so we will
        # really have a list of all system call nrs. for x86-64 in the x86-64
        # ABI entry.
        self.abis = {}
        # a dict of all system call names encountered across mapping to a list
        # of ABIs where it was encountered.
        self.syscalls_names = {}

    def run(self):
        self.args = self.parser.parse_args()

        if self.args.list_archs:
            print('\n'.join(list(sorted(self.ARCH_TABLE_PATHS.keys()))))
            return

        for arch in self.args.archs:
            if arch not in self.ARCH_TABLE_PATHS:
                print(f"Bad --arch value: '{arch}'")
                return

        self.parse()

        if self.args.list_raw:
            self.printRaw()
            return

        self.transformABIs()
        self.recordSyscallNames()

        if self.args.list_abis:
            self.printABIs()
            return

        if self.args.list_all_syscalls:
            self.printAllSyscalls()
            return

        if self.args.list_unique:
            self.printUniqueSyscalls()
            return

        if self.args.show_diff:
            abis = self.args.show_diff.split(':')
            if len(abis) != 2:
                printe("--show-diff: expected ABI1:ABI2 format", fail=True)
            for abi in abis:
                if abi not in self.abis:
                    printe(f"--show-diff: unknown ABI '{abi}'", fail=True)
            self.showDiff(*abis)
            return

        self.printSummary()

    def parse(self):
        for arch, subpath in self.ARCH_TABLE_PATHS.items():
            if arch not in self.args.archs:
                continue
            table = self.syscalls.setdefault(arch, {})
            with open(os.path.join(self.args.kernel_root, subpath)) as fl:
                self.processTable(subpath, arch, table, fl)

    def processTable(self, subpath, arch, table, fl):
        linenr = 0
        for line in fl.readlines():
            linenr += 1
            line = line.strip()

            if line.startswith('#'):
                continue

            parts = line.split()

            if not parts:
                # empty line
                continue
            elif len(parts) < 3:
                printe(f"Parse error in {subpath}:{linenr}: '{line}'")
                continue

            nr, abi, name = parts[:3]

            # these don't seem relevant much, it is for cell processors
            # (synergistic processing unit) and more kind of a hack, let's
            # ignore it for now
            if arch == "powerpc" and abi in ("spu", "nospu"):
                continue

            # the rest of the fields is optional

            compat_entry = parts[3] if len(parts) > 3 else None
            # '-' means it's just a placeholder
            if compat_entry and compat_entry == "-":
                compat_entry = None

            noreturn = len(parts) > 4 and parts[4] == "noreturn"

            entry = TableEntry(int(nr), abi, name, compat_entry, noreturn)

            calls = table.setdefault(abi, [])
            calls.append(entry)

    def transformABIs(self):
        if "x86-32" in self.syscalls:
            # this one is easy, every entry is for the i386 ABI
            entries = self.syscalls["x86-32"]["i386"]
            self.abis["i386"] = entries

        if "x86-64" in self.syscalls:
            # here we have three different "ABIs":
            # common: the same for x32 and x64
            # 64: x64 only
            # x32: x32 only
            abi_dict = self.syscalls["x86-64"]
            common = abi_dict["common"]

            self.abis["x64"] = copy.copy(common)
            self.abis["x32"] = copy.copy(common)
            self.abis["x64"].extend(abi_dict["64"])
            self.abis["x32"].extend(abi_dict["x32"])

            # skeep both ABIs sorted by system call nr.
            self.abis["x64"].sort(key=lambda e: e.nr)
            self.abis["x32"].sort(key=lambda e: e.nr)

    def recordSyscallNames(self):
        for abi, entries in self.abis.items():
            for entry in entries:
                abi_list = self.syscalls_names.setdefault(entry.name, [])
                abi_list.append(abi)

    def printRaw(self):
        for arch, abi_dict in self.syscalls.items():
            print(arch)
            for abi, entries in abi_dict.items():
                print("\t" + abi)
                for entry in entries:
                    print(f"\t\t{entry.nr} {entry.name}")

    def printABIs(self):
        for abi, entries in self.abis.items():
            print(abi)
            for entry in entries:
                print(f"\t{entry.nr} {entry.name}")

    def printAllSyscalls(self):
        for name in sorted(self.syscalls_names.keys()):
            print(f"{name}: ", end='')
            print(", ".join(self.syscalls_names[name]))

    def printUniqueSyscalls(self):
        for abi, entries in self.abis.items():
            print(f"Unique system calls in ABI '{abi}':\n")
            found = False
            for entry in entries:
                if len(self.syscalls_names[entry.name]) == 1:
                    print(f"\t{entry.nr} {entry.name}")
                    found = True
            if not found:
                print("\tN/A")
            print()

    def showDiff(self, abi1, abi2):
        print(f"Differences between {abi1} and {abi2}\n")

        abi1_map = {}
        abi2_map = {}
        only_in_abi1 = []
        only_in_abi2 = []
        mismatches = []

        for entry in self.abis[abi1]:
            abi1_map[entry.name] = entry.nr
            known_abis = self.syscalls_names[entry.name]
            if abi2 not in known_abis:
                only_in_abi1.append(entry)

        for entry in self.abis[abi2]:
            abi2_map[entry.name] = entry.nr
            known_abis = self.syscalls_names[entry.name]
            if abi1 not in known_abis:
                only_in_abi2.append(entry)
            else:
                other_nr = abi1_map[entry.name]
                if entry.nr != other_nr:
                    mismatches.append(entry)

        if only_in_abi1:
            print("System calls only found in", abi1 + "\n")
            for entry in only_in_abi1:
                print(f"\t{entry.nr} {entry.name}")
            print()

        if only_in_abi2:
            print("System calls only found in", abi2 + "\n")
            for entry in only_in_abi2:
                print(f"\t{entry.nr} {entry.name}")
            print()

        if mismatches:
            print("System calls with differing numbers\n")
            for entry in mismatches:
                nr1 = abi1_map[entry.name]
                nr2 = abi2_map[entry.name]
                print(f"\t{entry.name} ({abi1} = {nr1}, {abi2} = {nr2})")

    def printSummary(self):
        print("Successfully processed .tbl files.\n")
        print("Overall number of different system calls across ABIs:", len(self.syscalls_names))

        for abi, entries in self.abis.items():
            print(f"ABI '{abi}': found {len(entries)} system calls")


parser = TableParser()
parser.run()
