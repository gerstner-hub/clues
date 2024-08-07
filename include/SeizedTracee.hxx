#pragma once

// clues
#include <clues/Tracee.hxx>

namespace clues {

/// Specialization of Tracee that attaches to an existing, unrelated process in the system.
class CLUES_API SeizedTracee :
		public Tracee {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	SeizedTracee(EventConsumer &consumer);

	~SeizedTracee() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const cosmos::ProcessID tracee);

	void attach() override;
	void detach() override;

	void wait(cosmos::WaitRes &res) override;
};

} // end ns
