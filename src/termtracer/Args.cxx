#include "Args.hxx"

namespace clues {

Args::Args() :
	cmdline{"Command line process tracer.\nTo use clues as a front-end pass the command line to execute after '--'", ' ', "0.1"},
	attach_proc{
		"p", "process",
		"attach to the given already running process for tracing",
		false,
		cosmos::to_integral(cosmos::ProcessID::INVALID),
		"Process ID"},
	follow_execve{
		"", "follow-execve",
		"What to do upon execve() in a tracee: 'yes' (continue tracing; default), 'no' (detach from tracee), 'ask' (interactively ask what to do), 'path:<path>' (continue if new executable matches path), 'glob:<pattern>' (continue if new executable matches glob pattern)",
		false,
		"",
		"configuration string"
	},
	verbose{
		"v", "verbose",
		"increase verbosity of tracing output",
		false},
	max_value_len{
		"s", "max-len",
		"maximum length of parameter values to print. 0 to to print not at all, -1 to disable truncation",
		false,
		64,
		"number of bytes"} {

	cmdline.add(attach_proc);
	cmdline.add(follow_execve);
	cmdline.add(verbose);
	cmdline.add(max_value_len);
}

} // end ns
