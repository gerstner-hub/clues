#pragma once

// clues
#include <clues/SystemCall.hxx>

namespace clues {

/// Stores information about each system call number in form of SystemCall objects.
/**
 * This is a caching map object. It doesn't fill in all system calls at once,
 * but fills in each system call as it comes up.
 **/
class SystemCallDB :
		protected std::map<SystemCallNr, SystemCall*> {
public: // functions

	SystemCallDB() = default;

	// non-copyable semantics
	SystemCallDB(const SystemCallDB &) = delete;
	SystemCallDB& operator=(const SystemCallDB &) = delete;

	~SystemCallDB();

	SystemCall& get(const SystemCallNr nr);

	const SystemCall& get(const SystemCallNr nr) const {
		return const_cast<SystemCallDB&>(*this).get(nr);
	}

protected: // functions

	SystemCall* createSysCall(const SystemCallNr nr);
};

} // end ns
