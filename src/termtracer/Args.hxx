#pragma once

// TCLAP
#include <tclap/CmdLine.h>

// cosmos
#include <cosmos/proc/process.hxx>

namespace clues {

struct Args {
protected:
	TCLAP::ValuesConstraint<std::string> m_abi_constraint;

	std::vector<std::string> getABIs();
public:
	Args();

	TCLAP::CmdLine cmdline;
	/// Already running process to attach to.
	TCLAP::ValueArg<std::underlying_type<cosmos::ProcessID>::type> attach_proc;
	/// Controls the behaviour upon execve().
	TCLAP::ValueArg<std::string> follow_execve;
	/// controls the behaviour upon clone()/fork().
	TCLAP::ValueArg<std::string> follow_children;
	/// controls whether threads within the same process are followed.
	TCLAP::SwitchArg follow_threads;
	/// Short form of 'follow_children yes'
	TCLAP::SwitchArg follow_children_switch;
	/// Don't attach all other threads even if `follow_children_switch` is set.
	TCLAP::SwitchArg no_initial_threads_attach;
	/// Increase verbosity of tracing output.
	TCLAP::SwitchArg verbose;
	/// Maximum length of parameter values to print.
	TCLAP::ValueArg<int> max_value_len;
	/// List system call names and their numbers.
	TCLAP::SwitchArg list_syscalls;
	/// List ABI-specific system call names and their numbers.
	TCLAP::ValueArg<std::string> list_abi_syscalls;
	/// List supported system call ABIs
	TCLAP::SwitchArg list_abis;
	/// Configure system calls which to trace.
	TCLAP::ValueArg<std::string> syscall_filter;
};

} // end ns
