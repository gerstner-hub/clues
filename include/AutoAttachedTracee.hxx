#pragma once

// clues
#include <clues/Tracee.hxx>

namespace clues {

/// Specialization of Tracee for automatically attached child tracees.
/**
 * Automatically attached children will report a ptrace-event stop as initial
 * activity.
 **/
class CLUES_API AutoAttachedTracee :
		public Tracee {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	AutoAttachedTracee(Engine &engine, EventConsumer &consumer);

	~AutoAttachedTracee() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const Tracee &parent, const cosmos::ProcessID pid);
};

} // end ns

