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
        self.parser.add_argument("--generate-headers", metavar="DIR",
                                 help="Generate C++ headers for the selected architectures in the given directory",
                                 default=None)

        # all parsed systems calls as they appear in the table file for an
        # arch in the following structure:
        # "arch" → "abi" → [list of TableEntry]
        self.parsed = {}
        # transformed data in a dictionary of the following structure:
        # "abi" → [list of TableEntry]
        # where all system calls for an ABI are resolved, so that there
        # will be a complete list of all system call nrs. for x86-64 in the
        # x86-64 ABI entry, for example.
        self.abis = {}
        # a dict of all system call names encountered mapped to a list of ABIs
        # where they have been seen.
        self.syscall_names = {}

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

        if self.args.generate_headers:
            self.generateHeaders(self.args.generate_headers)
            return

        self.printSummary()

    def parse(self):
        for arch, subpath in self.ARCH_TABLE_PATHS.items():
            if arch not in self.args.archs:
                continue
            table = self.parsed.setdefault(arch, {})
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

            # some system call names have an underscore prefix for some
            # reason, this doesn't help us much here
            name = name.lstrip("_")

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
        if "x86-32" in self.parsed:
            # this one is easy, every entry is for the i386 ABI
            entries = self.parsed["x86-32"]["i386"]
            self.abis["i386"] = entries

        if "x86-64" in self.parsed:
            # here we have three different "ABIs":
            # common: the same for x32 and x64
            # 64: x64 only
            # x32: x32 only
            abi_dict = self.parsed["x86-64"]
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
                abi_list = self.syscall_names.setdefault(entry.name, [])
                abi_list.append(abi)

    def printRaw(self):
        for arch, abi_dict in self.parsed.items():
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
        for name in sorted(self.syscall_names.keys()):
            print(f"{name}: ", end='')
            print(", ".join(self.syscall_names[name]))

    def printUniqueSyscalls(self):
        for abi, entries in self.abis.items():
            print(f"Unique system calls in ABI '{abi}':\n")
            found = False
            for entry in entries:
                if len(self.syscall_names[entry.name]) == 1:
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
            known_abis = self.syscall_names[entry.name]
            if abi2 not in known_abis:
                only_in_abi1.append(entry)

        for entry in self.abis[abi2]:
            abi2_map[entry.name] = entry.nr
            known_abis = self.syscall_names[entry.name]
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
        print("Overall number of different system calls across ABIs:", len(self.syscall_names))

        for abi, entries in self.abis.items():
            print(f"ABI '{abi}': found {len(entries)} system calls")

    def generateHeaders(self, outdir):
        print("Generating headers into", outdir)
        with open(os.path.join(outdir, "syscallnrs.hxx"), 'w') as generic_header_fd:
            self.writeGenericHeader(generic_header_fd)

        for abi, table in self.abis.items():
            with open(os.path.join(outdir, f"syscallnrs_{abi}.hxx"), 'w') as abi_header_fd:
                self.writeABIHeader(abi_header_fd, abi, table)

    def normalizedSyscalls(self):
        """Returns a normalized version of self.syscall_names which merges ABI
        specific variants of system calls.

        This currently mostly affects i386 with 32/64 bit variants of system
        calls for:

        - uid_t/gid_t
        - off_t
        - time_t

        For the generic systemcallnrs.hxx we merge these and provide the
        variant information in a comment to make things clearer.

        TODO:

        This is an experimental approach at the moment. From an in-program API
        POV it can be good to be able to express something like "tell me if
        this is any of the getuid() system calls". Other contexts might want
        the more specific information, is this really a 64-bit getuid()
        systemm call?
        For system call filtering this is similarly problematic. strace
        supports specification of things like `-e fadvise64_64`. Implementing
        ABI specific filter while merging common system calls will be
        difficult.

        Update:

        It will be better to private three types of enums:

        - "global" SysCallNrs which contain all known system call names across
          all ABIs, leaving variants as they are.
        - native ABI SysCallNrs whic correspond to the exact system call
          number the kernel users for the ABI.
        - normalized SysCallNrs which contain the normalize system calls,
          hiding differences between ABIs.
        """

        ret = copy.copy(self.syscall_names)

        def is386_only(abis):
            return len(abis) == 1 and abis[0] == "i386"

        for name, abis in self.syscall_names.items():
            if not is386_only(abis):
                continue

            if name.endswith("32"):
                # this is a 32-bit wide UID/GID related system call, merge it
                # with the 64-bit variant.
                del ret[name]
                brother = name.rstrip("32")
                abis2 = ret[brother]
                abis2.remove("i386")
                abis2.extend(["i386:uid32", "i386:uid64"])
                abis2.sort()
            elif name.endswith("time64"):
                # some have an additional _time64 suffix, some only a 64 suffix
                # compared to the "normal" version
                brother = name.rstrip("64")
                if brother not in ret:
                    brother = name.rsplit('_', 1)[0]
                abis2 = ret[brother]
                try:
                    abis2.remove("i386")
                    abis2.extend(["i386:time32", "i386:time64"])
                except ValueError:
                    # some system calls only exit in 64-bit variants on i386
                    abis2.append("i386:time64")
                abis2.sort()
                del ret[name]
            elif name.endswith("64"):
                # these are file system off_t 32/64 bit differences
                brother = name.rstrip("64")
                if brother not in ret:
                    # for fadvise64_64
                    brother = name.rsplit('_', 1)[0]
                abis2 = ret[brother]
                abis2.remove("i386")
                abis2.extend(["i386:off32", "i386:off64"])
                abis2.sort()
                del ret[name]

        return ret

    def writeGenericHeader(self, fd):
        fd.write("#pragma once\n\n")
        fd.write("#include <array>\n")
        fd.write("#include <cstddef>\n")
        fd.write("#include <map>\n")
        fd.write("#include <string_view>\n")
        fd.write("\n")
        fd.write("namespace clues {\n\n")
        fd.write("""
/// Abstract system call number usable across architectures and ABIs.
/**
 * This enum contains all known system calls across supported Linux
 * architectures and ABIs. These are abstract in the sense that their
 * numerical values don't correspond to the actual system call numbers
 * used by the kernel.
 **/\n""")
        fd.write("enum class SystemCallNr {\n")

        syscalls = self.syscall_names
        max_label = max([len(ident) for ident in syscalls.keys()])

        fd.write(f"\t{'UNKNOWN = 0,'.ljust(max_label+1)} // present in ...\n")

        for syscall in sorted(syscalls.keys()):
            abis = syscalls[syscall]
            ident = syscall.upper()
            ident += ","
            fd.write(f"\t{ident.ljust(max_label+1)} // {' '.join(abis)}\n")
        fd.write("};\n\n")

        fd.write(f"constexpr size_t SYSTEM_CALL_COUNT = {len(syscalls)};\n\n")

        fd.write("constexpr std::array<std::string_view, SYSTEM_CALL_COUNT> SYSTEM_CALL_NAMES = {\n")
        for syscall in sorted(syscalls.keys()):
            fd.write(f"\t\"{syscall}\",\n")
        fd.write("};\n\n")

        fd.write("const std::map<std::string_view, SystemCallNr> SYSTEM_CALL_NAME_MAP = {\n")
        for syscall in sorted(syscalls.keys()):
            fd.write(f"\t{{std::string_view{{\"{syscall}\"}}, SystemCallNr::{syscall.upper()}}},\n")
        fd.write("};\n\n")

        fd.write("} // end ns\n")

    def writeABIHeader(self, fd, abi, table):
        fd.write("#pragma once\n\n")
        fd.write("#include <stdint.h>\n")
        fd.write("#include \"syscallnrs.hxx\"\n")
        fd.write("\n")
        abi_comment = self.getABIComment(abi).strip()
        abi_comment = '\n'.join([' * ' + line for line in abi_comment.splitlines()])
        fd.write(f"/**\n{abi_comment}\n **/\n\n")
        fd.write("namespace clues {\n")
        fd.write(f"""
/// Native system call numbers as used by Linux on the {abi} ABI.
/**
 * This strong enum type represents a system call number on the {abi} ABI.
 * The literal values correspond exactly to the numbers used by the operating
 * system and reported by the ptrace() API for this ABI.
 *
 * The underlying data type corresponds to the type used in the
 * `PTRACE_GET_SYSCALL_INFO` API and is the same for all ABIs.
 **/
""")
        enum_ident = f"SystemCallNr{abi.upper()}"
        fd.write(f"enum class {enum_ident} : uint64_t {{\n")
        max_ident = max([len(entry.name) for entry in table])

        for entry in sorted(table, key=lambda el: el.nr):
            ident = entry.name.upper()
            comment = self.getABIEntryComment(abi, entry)
            if comment:
                comment = f" // {comment}"
            fd.write(f"\t{ident.ljust(max_ident+1)} = {entry.nr},{comment}\n")
        fd.write("};\n\n")

        fd.write(f"constexpr inline clues::SystemCallNr toGeneric(const {enum_ident} nr) {{\n")
        fd.write("\tswitch (nr) {\n")
        fd.write("\t\tdefault: return SystemCallNr::UNKNOWN;\n")
        for entry in sorted(table, key=lambda el: el.nr):
            ident = entry.name.upper()
            fd.write(f"\t\tcase {enum_ident}::{ident}: return clues::SystemCallNr::{ident};\n")
        fd.write("\t}\n")
        fd.write("}\n")

        fd.write("\n} // end ns\n")

    def getABIEntryComment(self, abi, entry):
        """Returns a comment to place after the given system call nr. enum."""
        if abi in ("x64", "x32"):
            if entry.abi == "common":
                return "common between x64 and x32"
            else:
                return f"specific to {abi}"

        return ""

    def getABIComment(self, abi):
        """Returns a global comment for the given API to place at the top of
        the header"""
        if abi == "i386":
            return """
This ABI is used for real 32-bit x86 kernels as well as for the 32-bit
emulation when running on x64 kernels.
"""
        elif abi == "x32":
            return """
This ABI is based on the AMD64 instruction set but uses only 32-bit pointers
and integers to reduce memory footprint.
"""
        elif abi == "x64":
            return """
This is the standard AMD64 ABI for 64-bit x86 kernels.
"""

        return ""


parser = TableParser()
parser.run()
