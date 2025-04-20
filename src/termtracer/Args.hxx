#pragma once

// TCLAP
#include <tclap/CmdLine.h>

// cosmos
#include <cosmos/proc/process.hxx>

namespace clues {

struct Args {
	Args();

	TCLAP::CmdLine cmdline;
	/// Already running process to attach to.
	TCLAP::ValueArg<std::underlying_type<cosmos::ProcessID>::type> attach_proc;
	/// Controls the behaviour upon execve().
	TCLAP::ValueArg<std::string> follow_execve;
	/// Increase verbosity of tracing output.
	TCLAP::SwitchArg verbose;
	/// Maximum length of parameter values to print.
	TCLAP::ValueArg<int> max_value_len;
};

} // end ns
