#pragma once

// clues
#include <clues/Tracee.hxx>

namespace clues {

/// Specialization of Tracee that attaches to an existing, unrelated process in the system.
class CLUES_API ForeignTracee :
		public Tracee {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	/**
	 * TODO: `sibling` could be left out when we always determined the
	 * thread-group-id of each Tracee and keep track of which tracees
	 * belong to which thread group. This could make sense anyway, since
	 * it is not always an AttachThreads context that might cause a Tracee
	 * to be added.
	 **/
	ForeignTracee(Engine &engine, EventConsumer &consumer, TraceePtr sibling = nullptr);

	~ForeignTracee() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const cosmos::ProcessID tracee);
};

} // end ns
