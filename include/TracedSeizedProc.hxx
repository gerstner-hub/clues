#pragma once

// clues
#include <clues/TracedProc.hxx>

namespace clues {

/// Specialization of TracedProc that attaches to an existing, unrelated process in the system.
class CLUES_API TracedSeizedProc :
		public TracedProc {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	TracedSeizedProc(EventConsumer &consumer);

	~TracedSeizedProc() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const cosmos::ProcessID tracee);

	void attach() override;
	void detach() override;

	void wait(cosmos::WaitRes &res) override;
};

} // end ns
