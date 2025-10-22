#!/usr/bin/python3

# This script parses .tbl files from the Linux kernel source tree and can
# generate C++ headers providing enums for the various architectures and ABIs
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
    kwargs["file"] = sys.stderr
    try:
        fail = kwargs.pop("fail")
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
    """Parse *.tbl files as found in the kernel source tree.

    After parsing you can access the parsed data in the `parsed`, `abis` and
    `syscall_names` members.
    """

    # keeping architecture and ABI apart is quite difficult here due to the
    # naming scheme and different approaches used between architectures.
    #
    # the architecture keys here relate to the combination of arch
    # sub-directory and syscall .tbl suffix, if any.
    #
    # each syscall .tbl might contain multiple ABIs, depending on the arch.
    #
    # the keys here are currently composed of the arch sub-directory plus the
    # <suffix> of the *.tbl file, if present.
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

    def __init__(self, kernel_root, archs):

        self.kernel_root = kernel_root
        self.archs = archs

        # all parsed systems calls as they appear in the table file for an
        # arch in the following structure:
        # "arch" → "abi" → [list of TableEntry]
        self.parsed = {}
        # transformed data in a dictionary of the following structure:
        # "abi" → [list of TableEntry]
        # where all system calls for an ABI are resolved, so that there
        # will be a complete list of all system call nrs. For x86-64 in the
        # x86-64 ABI entry, for example.
        self.abis = {}
        # a dict of all system call names encountered mapped to a list of ABIs
        # where they have been seen.
        self.syscall_names = {}

    def parse(self):
        kernel_root = self.kernel_root

        release_subpath = "include/config/kernel.release"
        with open(os.path.join(kernel_root, release_subpath)) as rl:
            self.kernel_release = rl.read().strip()

        for arch, subpath in self.ARCH_TABLE_PATHS.items():
            if arch not in self.archs:
                continue
            table = self.parsed.setdefault(arch, {})
            with open(os.path.join(kernel_root, subpath)) as fl:
                self.processTable(subpath, arch, table, fl)

    def process(self):
        self.parse()
        self.transformABIs()
        self.recordSyscallNames()

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

            # keep both ABIs sorted by system call nr.
            self.abis["x64"].sort(key=lambda e: e.nr)
            self.abis["x32"].sort(key=lambda e: e.nr)

    def recordSyscallNames(self):
        for abi, entries in self.abis.items():
            for entry in entries:
                abi_list = self.syscall_names.setdefault(entry.name, [])
                abi_list.append(abi)


class SourceGenerator:
    """Generates C++ headers and sources that model the parsed system call number
    information for selected architectures."""

    # this bit is or'ed into all the X32 system call numbers
    # this is all the difference visible to X86_64 in ptrace() when X32 system
    # calls occur.
    X32_SYSCALL_BIT = 0x40000000

    def __init__(self, parser, src_dir, inc_dir, inc_prefix, template):
        self.parser = parser
        self.src_dir = src_dir
        self.inc_dir = inc_dir
        self.inc_prefix = inc_prefix
        self.template = template

    def getOutputPath(self, outdir, abi, suffix):
        base = self.template.format(abi=abi, suffix=suffix)
        return os.path.join(outdir, base)

    def getHeaderOutputPath(self, abi):
        os.makedirs(self.inc_dir, exist_ok=True)
        return self.getOutputPath(self.inc_dir, abi, "hxx")

    def getUnitOutputPath(self, abi):
        os.makedirs(self.src_dir, exist_ok=True)
        return self.getOutputPath(self.src_dir, abi, "cxx")

    def getEnumIdent(self, abi):
        return f"SystemCallNr{abi.upper()}"

    def generate(self):
        generic_header = self.getHeaderOutputPath("generic")
        self._gen_header = os.path.basename(generic_header)
        with open(generic_header, 'w') as fd:
            self.writeGenericHeader(fd)

        with open(self.getUnitOutputPath("generic"), 'w') as fd:
            self.writeGenericUnit(fd)

        self._abi_headers = []

        for abi, table in self.parser.abis.items():
            abi_header = self.getHeaderOutputPath(abi)
            self._abi_headers.append(os.path.basename(abi_header))
            with open(abi_header, 'w') as fd:
                self.writeABIHeader(fd, abi, table)

            with open(self.getUnitOutputPath(abi), 'w') as fd:
                self.writeABIUnit(fd, os.path.basename(abi_header), abi, table)

        with open(self.getHeaderOutputPath("types"), 'w') as fd:
            self.writeTypesHeader(fd)

        with open(self.getHeaderOutputPath("fwd"), 'w') as fd:
            self.writeFwdHeader(fd)

        with open(self.getHeaderOutputPath("all"), 'w') as fd:
            self.writeAllHeader(fd)

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
        system call?
        For system call filtering this is similarly problematic. strace
        supports specification of things like `-e fadvise64_64`. Implementing
        ABI specific filters while merging common system calls will be
        difficult.

        Update:

        It will be better to private three types of enums:

        - "global" SysCallNrs which contain all known system call names across
          all ABIs, leaving variants as they are.
        - native ABI SysCallNrs which correspond to the exact system call
          number the kernel users for the ABI.
        - normalized SysCallNrs which contain the normalize system calls,
          hiding differences between ABIs.
        """

        ret = copy.copy(self.syscall_names)

        def is386_only(abis):
            return abis == ["i386"]

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
        fd.write("#include <stdint.h>\n")
        fd.write("\n#include <clues/dso_export.h>\n")
        self.writePreamble(fd)
        fd.write("namespace clues {\n\n")
        fd.write("""
/// Abstract system call number usable across architectures and ABIs.
/**
 * This enum contains all known system calls across supported Linux
 * architectures and ABIs. These are abstract in the sense that their
 * numerical values don't correspond to the actual system call numbers
 * used by the kernel.
 *
 * For simplicity the underlying type for the abstract enum type is kept in
 * sync with the concrete system call number enum types.
 **/\n""")
        fd.write("enum class SystemCallNr : uint64_t {\n")

        syscalls = self.parser.syscall_names
        max_label = max([len(ident) for ident in syscalls.keys()])

        fd.write(f"\t{'UNKNOWN = 0,'.ljust(max_label+1)} // present in ...\n")

        for syscall in sorted(syscalls.keys()):
            abis = syscalls[syscall]
            ident = syscall.upper()
            ident += ","
            fd.write(f"\t{ident.ljust(max_label+1)} // {' '.join(abis)}\n")
        fd.write("};\n\n")

        fd.write(f"constexpr size_t SYSTEM_CALL_COUNT = {len(syscalls)+1};\n\n")

        fd.write("CLUES_API const extern std::array<std::string_view, SYSTEM_CALL_COUNT> SYSTEM_CALL_NAMES;\n\n")

        fd.write("CLUES_API const extern std::map<std::string_view, SystemCallNr> SYSTEM_CALL_NAME_MAP;\n\n")

        fd.write("} // end ns\n")

    def writeGenericUnit(self, fd):
        fd.write(f"#include <{self.inc_prefix}/generic.hxx>\n")
        fd.write("\n")
        self.writePreamble(fd)
        fd.write("namespace clues {\n\n")

        syscalls = self.parser.syscall_names

        fd.write("const std::array<std::string_view, SYSTEM_CALL_COUNT> SYSTEM_CALL_NAMES = {\n")
        fd.write("\t\"unknown\",\n")
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
        fd.write("\n#include <clues/dso_export.h>\n")
        fd.write("\n\n#include \"fwd.hxx\"\n")
        fd.write("\n")
        self.writePreamble(fd)
        abi_comment = self.getABIComment(abi).strip()
        abi_comment = '\n'.join([" * " + line for line in abi_comment.splitlines()])
        fd.write(f"/**\n{abi_comment}\n **/\n\n")
        fd.write("namespace clues {\n")
        fd.write(f"""
/// Native system call numbers as used by Linux on the {abi} ABI.
/**
 * This strong enum type represents a system call number on the {abi} ABI.
 * The literal values correspond to the numbers used by the operating
 * system and reported by the ptrace() API for this ABI.
 *
 * The underlying data type corresponds to the type used in the
 * `PTRACE_GET_SYSCALL_INFO` API and is the same for all ABIs.
 **/
""")
        self.writeABIHeaderSpecifics(fd, abi)

        enum_ident = self.getEnumIdent(abi)
        fd.write(f"enum class {enum_ident} : uint64_t {{\n")
        max_ident = max([len(entry.name) for entry in table])

        for entry in sorted(table, key=lambda el: el.nr):
            ident = entry.name.upper()
            comment = self.getABIEntryComment(abi, entry)
            if comment:
                comment = f" // {comment}"
            nr = self.getABISysNr(abi, entry)
            fd.write(f"\t{ident.ljust(max_ident+1)} = {nr},{comment}\n")
        fd.write("};\n\n")

        fd.write("/// Convert the native system call nr. into its generic representation.\n")
        fd.write(f"CLUES_API clues::SystemCallNr to_generic(const {enum_ident} nr);\n")

        fd.write("\n} // end ns\n")

    def getABISysNr(self, abi, entry):
        if abi == "x32":
            return f"X32_SYSCALL_BIT + {entry.nr}"
        else:
            return entry.nr

    def writeABIHeaderSpecifics(self, fd, abi):
        if abi == "x32":
            fd.write("\n/// This bit is set for all X32 system call to identify this ABI\n")
            fd.write(f"constexpr uint64_t X32_SYSCALL_BIT = {hex(self.X32_SYSCALL_BIT)};\n\n")

    def writeABIUnit(self, fd, inc_base, abi, table):
        fd.write(f"#include <{self.inc_prefix}/{inc_base}>\n")
        fd.write(f"#include <{self.inc_prefix}/{self._gen_header}>\n")
        fd.write("\n")
        self.writePreamble(fd)
        fd.write("namespace clues {\n\n")
        fd.write("""/*
 * TODO: this is a very big switch statement which will need to be
 * invoked for every new system call entry.
 * for now we trust the compiler to generate efficient code here, but
 * it could hurt tracing performance if this is not as good as we hope
 * it to be. Using an alternative data structure like std::map could
 * help here in this case.
 * This needs a closer investigation at a later time.
 */\n""")
        enum_ident = self.getEnumIdent(abi)
        fd.write(f"clues::SystemCallNr to_generic(const {enum_ident} nr) {{\n")
        fd.write("\n")
        fd.write("\tswitch (nr) {\n")
        fd.write("\t\tdefault: return SystemCallNr::UNKNOWN;\n")
        for entry in sorted(table, key=lambda el: el.nr):
            ident = entry.name.upper()
            fd.write(f"\t\tcase {enum_ident}::{ident}: return clues::SystemCallNr::{ident};\n")
        fd.write("\t}\n")
        fd.write("}\n\n")
        fd.write("} // end ns\n")

    def writeTypesHeader(self, fd):
        fd.write("#pragma once\n\n")
        fd.write("#include <variant>\n")
        fd.write("\n#include \"fwd.hxx\"\n")
        fd.write("\n")
        self.writePreamble(fd)

        fd.write("namespace clues {\n\n")

        abi_enums = []
        for abi in self.parser.abis:
            ident = self.getEnumIdent(abi)
            abi_enums.append(ident)

        fd.write("using SystemCallNrVariant = std::variant<")
        for nr, enum in enumerate(abi_enums):
            fd.write(f"{enum}")
            if nr != len(abi_enums) - 1:
                fd.write(", ")
        fd.write(">;\n")

        fd.write("\n} // end ns\n")

    def writeFwdHeader(self, fd):
        fd.write("#pragma once\n\n")
        fd.write("namespace clues {\n\n")
        fd.write("enum class SystemCallNr : uint64_t;\n")
        for abi in self.parser.abis:
            ident = self.getEnumIdent(abi)
            fd.write(f"enum class {ident} : uint64_t;\n")
        fd.write("\n} // end ns\n")

    def writeAllHeader(self, fd):
        fd.write("#pragma once\n\n")
        for base in ("generic", "types"):
            path = self.getOutputPath(self.inc_prefix, base, "hxx")
            fd.write(f"#include <{path}>\n")
        for abi in self.parser.abis:
            path = self.getOutputPath(self.inc_prefix, abi, "hxx")
            fd.write(f"#include <{path}>\n")

    def writePreamble(self, fd):
        script = os.path.basename(__file__)
        BANNER_LEN = 80
        fd.write("\n/" + "*" * BANNER_LEN + "\n")
        fd.write(f" * this file was generated by {script}\n")
        fd.write(f" * based on Linux kernel sources {self.parser.kernel_release}\n")
        fd.write(" " + "*" * BANNER_LEN + "/\n\n")

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
            # TODO: need to verify during runtime if everything adds up here.
            # it might make more sense to actually add the X32 syscall bit in
            # the enum already to avoid extra complications.
            return """
This ABI is based on the AMD64 instruction set but uses only 32-bit pointers
and integers to reduce memory footprint.

The system call numbers have a high bit set to indicate the X32 ABI, which
means that the system call numbers reported by ptrace() don't directly
correspond to the values seen here.
"""
        elif abi == "x64":
            return """
This is the standard AMD64 ABI for 64-bit x86 kernels.
"""

        return ""


class Main:
    """Main utility class offering a CLI interface to parse *.tbl files and
    generate C++ code."""

    def getArgParser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--kernel-root",
            default="/usr/src/linux",
            help="where to look for .tbl files to parse")
        parser.add_argument("--archs", nargs="*",
            help="Architectures which should be processed",
            default=TableParser.ARCH_TABLE_PATHS.keys())
        parser.add_argument("--list-archs", action="store_true",
            help="list valid arguments for --archs")
        parser.add_argument("--list-raw", action="store_true",
            help="list raw content parsed from .tbl files")
        parser.add_argument("--list-abis", action="store_true",
            help="list expanded ABI information after processing .tbl files")
        parser.add_argument("--list-all-syscalls", action="store_true",
            help="list every distinct system call and the ABIs they're found in")
        parser.add_argument("--list-unique", action="store_true",
            help="list system calls that are unique for each ABI")
        parser.add_argument("--show-diff", metavar="ABI1:ABI2",
            help="Show differences between the given ABIs")
        parser.add_argument("--generate-sources",
            help="Generate C++ sources for the selected architectures in the given directory",
            action="store_true")
        parser.add_argument("--name-template",
            default="{abi}.{suffix}",
            help="template for generated header filenames. {abi} will be replaced by the respective ABI the header is for, {suffix} by .hxx or .cxx.")
        parser.add_argument("--include-prefix",
            default="clues/sysnrs",
            help="prefix to add for #include directives for generated headers")
        parser.add_argument("--src-outdir", metavar="DIR",
            help="Directory where to place generated source files",
            default="src/sysnrs")
        parser.add_argument("--inc-outdir", metavar="DIR",
            help="Directory where to place generated include files",
            default="include/sysnrs")

        return parser

    def run(self):
        self.args = self.getArgParser().parse_args()

        if self.args.list_archs:
            print('\n'.join(list(sorted(TableParser.ARCH_TABLE_PATHS.keys()))))
            return

        for arch in self.args.archs:
            if arch not in TableParser.ARCH_TABLE_PATHS:
                print(f"Bad --arch value: '{arch}'")
                return

        self.parser = TableParser(self.args.kernel_root, self.args.archs)
        self.parser.process()

        if self.args.list_raw:
            self.printRaw()
            return

        if self.args.list_abis:
            self.printABIs()
        elif self.args.list_all_syscalls:
            self.printAllSyscalls()
        elif self.args.list_unique:
            self.printUniqueSyscalls()
        elif self.args.show_diff:
            abis = self.args.show_diff.split(':')
            if len(abis) != 2:
                printe("--show-diff: expected ABI1:ABI2 format", fail=True)
            for abi in abis:
                if abi not in self.parser.abis:
                    printe(f"--show-diff: unknown ABI '{abi}'", fail=True)
            self.showDiff(*abis)
        elif self.args.generate_sources:
            self.generateHeaders()
        else:
            self.printSummary()

    def printRaw(self):
        for arch, abi_dict in self.parser.parsed.items():
            print(arch)
            for abi, entries in abi_dict.items():
                print("\t" + abi)
                for entry in entries:
                    print(f"\t\t{entry.nr} {entry.name}")

    def printABIs(self):
        for abi, entries in self.parser.abis.items():
            print(abi)
            for entry in entries:
                print(f"\t{entry.nr} {entry.name}")

    def printAllSyscalls(self):
        names = self.parser.syscall_names
        for name in sorted(names.keys()):
            print(f"{name}: ", end='')
            print(", ".join(names[name]))

    def printUniqueSyscalls(self):
        for abi, entries in self.parser.abis.items():
            print(f"Unique system calls in ABI '{abi}':\n")
            found = False
            for entry in entries:
                if len(self.parser.syscall_names[entry.name]) == 1:
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

        for entry in self.parser.abis[abi1]:
            abi1_map[entry.name] = entry.nr
            known_abis = self.parser.syscall_names[entry.name]
            if abi2 not in known_abis:
                only_in_abi1.append(entry)

        for entry in self.parser.abis[abi2]:
            abi2_map[entry.name] = entry.nr
            known_abis = self.parser.syscall_names[entry.name]
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
        print("Overall number of different system calls across ABIs:", len(self.parser.syscall_names))

        for abi, entries in self.parser.abis.items():
            print(f"ABI '{abi}': found {len(entries)} system calls")

    def generateHeaders(self):
        print("Generating headers into", self.args.inc_outdir)
        print("Generating sources into", self.args.src_outdir)
        generator = SourceGenerator(self.parser, self.args.src_outdir,
                                    self.args.inc_outdir,
                                    self.args.include_prefix,
                                    self.args.name_template)

        generator.generate()


if __name__ == "__main__":
    main = Main()
    main.run()
