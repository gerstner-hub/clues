#pragma once

// clues
#include <clues/Tracee.hxx>

namespace clues {

/// Specialization of Tracee that attaches to an existing, unrelated process in the system.
class CLUES_API ForeignTracee :
		public Tracee {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	ForeignTracee(Engine &engine, EventConsumer &consumer);

	~ForeignTracee() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const cosmos::ProcessID tracee);
};

} // end ns
