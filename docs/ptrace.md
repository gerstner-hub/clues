Notes on the ptrace(2) API
==========================

Tracee States
-------------

A tracee can be running or stopped. System calls aren't considered to cause a
stopped state for the purposes of tracing (that is, if we're not tracing the
system calls, otherwise we'll have syscall-stop as described below).
`PTRACE_LISTEN` causes a bit of a grey area state in-between, but can
generally be considered similar to a group-stop as described below.

The following stop states are all reported as `WIFSTOPPED(status)`. They may
be differentiated by examining `status>>8` and if that still leaves ambiguity
then by querying `PTRACE_GETSIGINFO`.

**ptrace-stop** means: tracee is ready to accept ptrace commands

This state is further divided into the sub-states described in the following
sections.

### signal-delivery-stop

**Purpose**: The tracee is about to receive a signal, but it can still be
suppressed by the tracer.

**Detection**: `WIFSTOPPED(status)` is true, stop signal via `WSTOPSIG(status)`.
If the signal is SIGTRAP then the stop reason might still be different (see
`PTRACE_EVENT` stops). This could also be a group stop. See below.

**Continuing**: `ptrace(PTRACE_restart, pid, 0, sig);`

Here `restart` means any of the restart-related commands. If sig == 0 then no
signal will be delivered. This is called signal injection.

Signal injection only works in signal-delivery-stop, otherwise the sig number
may simply be ignored. For creating new signals, `tgkill()` should be used.

`SIGCONT` cannot be fully suppressed, the side effect of waking up all threads
of a group-stopped process will always happen. Only the execution of a SIGCONT
handler in the child can be suppressed. `SIGSTOP` **can** be suppressed though.

If `PTRACE_SETSIGINFO` is used to modify the signal delivery data, then the
`sig` parameter to `ptrace()` must match, otherwise the behaviour is undefined.

### group-stop

**Purpose**: A (possibly multithreaded) process receives a stopping signal. This
can be suppressed, but only if all threads are traced.

**Detection (old)**: like in signal-delivery-stop, but with additional checks.
It can only be a group-stop if it is `SIGSTOP`, `SIGTSTP`, `SIGTTIN` or
`SIGGTOU`. If it is one of these then `PTRACE_GETSIGINFO` needs to be checked
for `si_code` containing `PTRACE_EVENT_STOP`.

**Detection (new)** (`PTRACE_SEIZE`): check for `(status>>16) == PTRACE_STOP`
without having to invoke another system call.

**Continuing** (`PTRACE_SEIZE`): To avoid problems `PTRACE_LISTEN` should be
used to restart the tracee when in group-stop, only this way will the tracee
actually enter stopped state and future events will still be reported to the
tracer.

### `PTRACE_EVENT` stops

**Purpose**: These will result from the use of any of the `PTRACE_O_TRACE*`
options, or if a group-stop occurred.

**Detection**: `WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP`. The exact
event can be determined via (status>>8) == (`PTRACE_EVENT_[type]`<<8 |
SIGTRAP).

### syscall-stop (syscall-enter-stop, syscall-exit-stop)

**Purpose**: System call is entered or exited. Can be further sub-divided into
             syscall-enter-stop, syscall-exit-stop.

**Detection**: `WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP & 0x80)`.
This only works with `PTRACE_O_TRACESYSGOOD`, otherwise `GETSIGINFO` would need
to be invoked all the time, which is not recommended.
enter-stop and exit-stop are indistinguishable from each other, the tracer
needs to keep track of the sequence of stops in order to keep track of what is
happening.

When restarting via `PTRACE_SYSCALL` then an exit-stop event will be
generated. Even if a system call is interrupted by a signal, an exit-stop will
happen (signal-delivery-stop only after that). The exit-stop is still not
guaranteed to happen, the following exceptions exist:

- `PTRACE_EVENT` stop happens
- exit through `_exit(2)` or `exit_group(2)`
- exit through SIGKILL
- silent death via execve in another thread that is not traced.

Seccomp stops can cause exit-stops without a preceding entry-stop.

If the `PTRACE_SYSEMU*` methods or any method other than `PTRACE_SYSCALL` is
used for restarting during syscall-enter-stop, then no syscall-exit-stop will
be generated.

NOTE: the man page also talks about syscall-entry-stop.

### seccomp-stop (behaviour after kernel 4.7 from 2017)

**Purpose**: Occurs when a seccomp rule is triggered.

**Detection**: It seems there is no clear way to detect this, especially since
there may or may not be a syscall-enter-stop preceding this. Using
`GET_SYSCALL_INFO` might be a way to detect the seccomp-stop.

- seccomp-stop is not reported (and seccomp doesn't run) if a system call is skipped via
  `PTRACE_SYSEMU`.
- when resuming the child, seccomp will be rerun with a `SECCOMP_RET_TRACE`
  rule now functioning the same as a `SECCOMP_RET_ALLOW`.

### singlestep-stop

Not documented in the man page. Would only be needed for full debuggers, not
necessarily for what we have in mind for clues currently.

ptrace() Commands and Stopped State
-----------------------------------

Only the commands ATTACH, SEIZE, TRACEME, INTERRUPT and KILL are allowed in
any tracee state. All the other require the tracee to be in a stopped state.

So-called informational commands can only be issued in stopped state and also
keep the tracee in stopped state: PEEK\*, POKE\*, GET\*REG\*, SET\*REG\*,
GETSIGINFO, SETSIGINFO, GETEVENTTMSG, SETOPTIONS.
Some of these commands may seemingly succeed but do nothing or return
undefined data, if their use is not documented for the current ptrace stop
state.

The OPTIONS only affect a single tracee and replaces its current flags. The
flags are inherited to further child processes that are auto-attached.

A set of commands makes the tracee run again: `CONT`, `LISTEN`, `DETACH`,
`SYSCALL`, `SINGLESTEP`, `SYSEMU*`. They all specify a signal argument, which
will be the signal injected into the tracee if in signal-delivery-stop. For
other stops it is recommended to pass 0 as signal.

Dealing with exec()
-------------------

When a thread in a multithreaded process calls execve() then all other threads
will appear to `exit()` with 0 and generate and `EVENT_EXIT` stop. The thread
that called execve() will be reassigned the thread ID (PID) of the thread
group leader and replace him. This will all seem very confusing to tracers.

To fix this one should set the `PTRACE_O_TRACEEXEC` option. This way legacy
`SIGTRAP` generations for `execve()` are disabled. Instead a `EVENT_EXEC` stop
is generated, but only after all other threads of the process exited, except
for the thread group leader and the thread that calls `execve()`. Via
GETEVENTMSG the former thread ID can be obtained. When this event occurs, then
the tracer should remove data about all other threads of the process, only
keeping info about the only still running tracee where `thread ID == thread
group ID == process ID`.

Attaching to Processes
----------------------

- a direct child process can fork and call `PTRACE_TRACEME` to let the parent
  attach.
- the tracer can use `PTRACE_ATTACH` or `PTRACE_SEIZE`.
- `PTRACE_ATTACH` should no longer be used, since it's buggy and has
  restrictions.
- grand-childs can automatically be attached to via the TRACEFORK, TRACEVFORK,
  and TRACECLONE options. These grand-childs automatically receive a SIGSTOP
  so that the tracer can observe "signal-delivery-stop" on them.
- detaching via `PTRACE_DETACH` requires the tracee to be in stopped state. If
  the tracee is running then sending SIGSTOP via tgkill(2) is recommended.
  This has races by design, though.
