#pragma once

// clues
#include <clues/TracedProc.hxx>

namespace clues {

/// Specialization of TracedProc that creates a new child process for tracing.
class CLUES_API TracedSubProc :
		public TracedProc {
public: // functions

	/// Create a traced process by creating a new process from `prog_args`
	TracedSubProc(EventConsumer &consumer);

	~TracedSubProc() override;

	/// Set the child process executable and parameters to trace.
	void configure(const cosmos::StringVector &prog_args);
	void attach() override;
	void detach() override;

	/// The exit code of the sub-process, valid only after detach().
	cosmos::ExitStatus exitCode() const { return m_exit_code; }

	void wait(cosmos::WaitRes &res) override;

protected: // functions

protected: // data

	cosmos::ChildCloner m_cloner;
	/// sub-process we're tracing
	cosmos::SubProc m_child;
	cosmos::ExitStatus m_exit_code = cosmos::ExitStatus::SUCCESS;
};

} // end ns
