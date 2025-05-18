#pragma once

// C++
#include <map>

// clues
#include <clues/SystemCall.hxx>

namespace clues {

/// Stores information about each system call number in form of SystemCall objects.
/**
 * This is a caching map object. It doesn't fill in all system calls at once,
 * but fills in each system call as it comes up in a lazy manner.
 **/
class SystemCallDB {
public: // functions

	SystemCallDB() = default;

	// non-copyable semantics
	SystemCallDB(const SystemCallDB &) = delete;
	SystemCallDB& operator=(const SystemCallDB &) = delete;

	SystemCallDB(SystemCallDB &&other) {
		*this = std::move(other);
	}
	SystemCallDB& operator=(SystemCallDB &&other) {
		m_map = std::move(other.m_map);
		return *this;
	}

	SystemCall& get(const SystemCallNr nr);

	const SystemCall& get(const SystemCallNr nr) const {
		return const_cast<SystemCallDB&>(*this).get(nr);
	}

protected: // data

	// TODO: this could also be a std::array of fixed size
	// this would waste a bit of memory but reduce lookup complexity even
	// more.
	// SystemCall values could also be stored by-value instead of as
	// shared_ptr.
	// On the other hand for tracing more than one thread multiple
	// SystemCallDBs would need to be maintained. Initial cost is higher
	// for fixed sized arrays and non-lazy initialization, but runtime
	// cost should be lower and determinism greater.

	std::map<SystemCallNr, SystemCallPtr> m_map;
};

} // end ns
