#include "Args.hxx"

namespace clues {

Args::Args() :
	cmdline{"Command line process tracer.\nTo use clues as a front-end pass the command line to execute after '--'", ' ', "0.1"},
	attach_proc{
		"p", "process",
		"attach to the given already running process for tracing.",
		false,
		cosmos::to_integral(cosmos::ProcessID::INVALID),
		"Process ID"},
	follow_execve{
		"", "follow-execve",
		"What to do upon execve() in a tracee: 'yes' (continue tracing; default), 'no' (detach from tracee), 'ask' (interactively ask what to do), 'path:<path>' (continue if new executable matches path), 'glob:<pattern>' (continue if new executable matches glob pattern).",
		false,
		"",
		"configuration string"
	},
	follow_children{
		"", "follow-children",
		"What to do upon new child processes appearing via [v]fork() or clone(): 'yes' (automatically attach), 'no' (ignore; default), 'ask' (interactively ask what to do), 'threads' (only follow threads of the same process).",
		false,
		"",
		"configuration string"
	},
	follow_threads{
		"", "threads",
		"follow/attach all threads within the process. Do not follow fork(). synonym for '--follow-children threads'.",
		false},
	// TODO: it seems we need a better command line parsing library to
	// handle this in a more traditional manner
	follow_children_switch{
		"f", "follow",
		"synonym for '--follow-children yes'.",
		false},
	no_initial_threads_attach{
		"1", "no-initial-threads-attach",
		"when attaching to a running process, don't attach all of the process's threads, only the one specified via -p, even if --follow-children is set.",
		false},
	verbose{
		"v", "verbose",
		"increase verbosity of tracing output",
		false},
	max_value_len{
		"s", "max-len",
		"maximum length of parameter values to print. 0 to to print not at all, -1 to disable truncation.",
		false,
		64,
		"number of bytes"},
	list_syscalls{
		"", "list-syscalls",
		"list all known system calls names, then exit.",
		false},
	syscall_filter{
		"e", "filter",
		"configuration of system call filters. comma separated list of system call names, optionally prefixed with '!' to negate the meaning.",
		false,
		"",
		"comma separated list of system call names"}
	{

	cmdline.add(attach_proc);
	cmdline.add(follow_execve);
	cmdline.add(follow_children);
	cmdline.add(follow_threads);
	cmdline.add(follow_children_switch);
	cmdline.add(no_initial_threads_attach);
	cmdline.add(verbose);
	cmdline.add(max_value_len);
	cmdline.add(list_syscalls);
	cmdline.add(syscall_filter);
}

} // end ns
