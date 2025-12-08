Introduction
============

This is *clues*, a next-generation Linux system call tracing framework.
*clues* is currently two things, a general-purpose library (libclues) for
implementing custom system call tracing programs and a command line utility
based on this library, which resembles the well known `strace`.

The library is implemented in C++ and based on [libcosmos][cosmos], following
a strong type model wherever possible.

This project is still in early development and not suitable for production
yet. Most importantly only a fraction of the system calls supported by Linux
are currently covered. See the following sections for more details.

Motivation
==========

I started this project a long time ago with the idea of coming up with an
advanced tracing utility beyond what `strace` offered at the time. I also
wanted to learn more about the `ptrace()` API in Linux and how system calls
and system call tracing work.

For years the code base for this remained sketchy, but by now I managed to
arrive at a basic modern framework for tracing system calls on Linux. The
`ptrace()` API and related logic are complex beasts with many unknowns. I
believe a well-documented, clean and modern approach to system call tracing
would be a valuable addition to the Linux debugging tool set even today.

Project Goals
=============

The primary goal for *clues* at this point is to reach a feature set
comparable to what classic `strace` offers. To this end, support for all
existing Linux system calls still needs to be implemented, also covering the
most common architectures and system call ABIs currently in use. This alone
is already quite the endeavour, but I hope this goal is achievable within the
not too distant future.

Once this goal has been reached, *clues* can be extended to provide additional
features. Here I can imagine things like a curses based user interface for
interactive tracing, or even a fully-fledged graphical UI, as well as support
for a range of complex debugging scenarios, where `strace` is sometimes
lacking.

Since performance is a relevant aspect in system call tracing, the topic of
tracing overhead is also on my radar, but I did not yet perform any comparison
tests between `strace` and `clues`, mostly because not all system calls are
yet covered by *clues*.

What Already Works
==================

*clues* is by now able to keep track of a dynamic number of tracees, no matter
if they are direct child processes or unrelated processes that have been
attached to. This includes keeping apart the individual threads of a process,
which is a bit of a complex matter on Linux, since threads resemble processes
from a kernel point of view. *clues* also keeps track of ABI changes and
complex personality changes (e.g. when a multi-threaded process calls
`execve()`.

For each tracee *clues* keeps track of its state and lifetime, it can report
the various tracing events like signals, system call entry and exit and all
the details surrounding it.

*clues* has been successfully tested on the following architecture / system
call ABIs:

- i386
- x86\_64 including 32-bit emulation
- aarch64

With what is supported so far I am able to show that the current design is
good enough to extend to multiple architectures and also multiple ABIs in the
same build, like it is the case with 32-bit emulation on x86\_64. The major
groundwork thus has been completed and what is left is mostly the somewhat
tedious work of adding support for the many system calls that exist on Linux.

Adding support for additional architectures is only a moderate effort
currently. Most of the work lies in implementing any ABI-specific system calls
or variants of system calls. The difficulties mostly lie in testing the code
during runtime on the respective more exotic target architectures.

What is still Missing
=====================

The biggest lack at the moment is that only a small subset of the system calls
available on `x86_64` are currently implemented, for the others only the
system call name and its return value are decoded, ignoring the reset of the
system call parameters.

At the moment **63 of 470 system calls** present in the supported ABIs are
implemented in libclues.

Apart from that the `clues` command line utility is missing a lot of the
more advanced command line options that `strace` supports.

Dependencies
============

*clues* is supposed to come with a small footprint, which also extends to its
dependencies. Currently only [libcosmos][cosmos] and the TCLAP command line
parser library are required. Both are pulled in via Git submodules, so things
should be rather worry-free for the casual builder.

Building and Installing
=======================

*clues* uses the `SCons` build system. See [libcosmos's
README](https://github.com/gerstner-hub/libcosmos/blob/master/README.md) for
some hints about how to use it. In the default case simply run

```sh
scons install
```

Then you will find all installation artifacts in the `install` directory tree.

Usage of the Command Line Tool
==============================

Currently the `clues` utility supports most of the basic features known from
`strace`. To start a new process under tracer control, pass the program's
name or path and its arguments after `--` to terminate the `clues` related
parameters:

```sh
$ clues -- ls /tmp
<tracing output and `ls` output interleaved>
```

To attach to an already running process pass `-p`:

```sh
$ clues -p `pidof myprogram`
```

Restrict tracing to certain system calls:

```sh
$ clues -e openat -- ls /tmp
```

There exist further parameters to control whether threads and child processes
of the tracee should be followed, to control tracing output etc.

Usage of the Library
====================

Clients of the `libclues` library foremost need two ingredients:

- An instance of the `Engine` type. The `Engine` is the main knob where to
  configure tracing targets. To start tracing `Engine::trace()` needs to be
  called, which enters the tracing main loop, waiting for events and invoking
  callbacks. Multiple tracees can be monitored at once using a single `Engine`.
- An implementation of the `EventConsumer` interface needs to be registered at
  `Engine` which will receive callbacks for tracing events. Please refer to
  the class's API documentation for the details. Basically events like system
  call entry/exit, signals and state changes observed in a Tracee will be
  reported via this interface.

The `Tracee` class represents a single tracee (a multithreaded process
consists of multiple `Tracee` instances). During trace event stops the
associated `Tracee` instance can be used to further inspect or manipulate the
tracee.

The implementation of the `clues` command line tool in
`src/termtracer/TermTracer.cxx` should give you a first idea on how to use
`libclues`. For programmatically inspecting system call information during
trace stops I decided to go for dedicated class types for each type of system
call. These class types are found in the headers in the `include/syscalls`
directory. This means that in the end a lot of different specializations will
exist for the different system calls. I found this to be the most expressive
approach, however, because the system call data can be accessed in a
convenient, structured and typesafe manner, once a `SystemCall` object has
been casted to the proper type.

`libclues` operates single-threaded, this means only a single trace event can
be processed at once even if multiple tracees are configured and other events
would be available for processing. For tracing huge process trees it would be
nice to support multi-threaded tracing, with one tracer thread per tracee.
This would increase the already high complexity of the tracing logic even
more, however. Some aspects of tracing might even be become plain impossible
when trying to perform multi-threaded tracing. For this reason `clues` sticks
to single-threaded tracing for the time being.

[cosmos]: https://github.com/gerstner-hub/libcosmos
