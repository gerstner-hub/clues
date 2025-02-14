#pragma once

// clues
#include <clues/Tracee.hxx>

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
	void detach() override;

	/// The exit code of the sub-process, valid only after detach().
	cosmos::ExitStatus exitCode() const { return *m_exit_code; }

	void wait(cosmos::ChildData &data) override;

	void exited(const cosmos::ChildData &data) override {
		m_exit_code = *data.status;
	}

protected: // data

	/// sub-process we're tracing
	cosmos::SubProc m_child;
	std::optional<cosmos::ExitStatus> m_exit_code;
};

} // end ns
