#pragma once

// clues
#include <clues/Tracee.hxx>

// cosmos
#include <cosmos/proc/SubProc.hxx>

namespace clues {

/// Specialization of Tracee that creates a new child process for tracing.
class CLUES_API ChildTracee :
		public Tracee {
public: // functions

	/// Create a traced process by creating a new process from `prog_args`
	ChildTracee(EventConsumer &consumer);

	~ChildTracee() override;

	/// Create the child process with the given parameters.
	/**
	 * This only forks the process, but does not start executing the new
	 * program until attach() is called.
	 **/
	void create(const cosmos::StringVector &args);

protected: // Base class interface

	bool isChildProcess() const override {
		return true;
	}

	void cleanupChild() override;

protected: // data

	/// the sub-process we're tracing
	cosmos::SubProc m_child;
};

} // end ns
