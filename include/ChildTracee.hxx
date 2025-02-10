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

	/// Set the child process executable and parameters to trace.
	void configure(const cosmos::StringVector &prog_args);
	void attach() override;
	void detach() override;

	/// The exit code of the sub-process, valid only after detach().
	cosmos::ExitStatus exitCode() const { return m_exit_code; }

	void wait(cosmos::ChildData &data) override;

	void exited(const cosmos::ChildData &data) override {
		m_exit_code = *data.status;
	}

protected: // data

	cosmos::StringVector m_args;
	/// sub-process we're tracing
	cosmos::SubProc m_child;
	cosmos::ExitStatus m_exit_code = cosmos::ExitStatus::SUCCESS;
};

} // end ns
