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

	/* XXX: this could also be a std::array of fixed size.
	 * This would waste a some memory but reduce lookup complexity even
	 * more.
	 * Every Tracee maintains its own SystemCallDB and often a thread only
	 * uses a rather limited amount of system calls. There are about ~500
	 * different system calls, so allocating a fixed array would cost
	 * about 4 KiB per Tracee. For 100 Tracees, which would be a high load
	 * scenario, the cost would cost be 400 KiB for maintaining all the
	 * pointers to potential SystemCall instances.
	 *
	 * Initial cost is higher for fixed sized arrays and non-lazy
	 * initialization, but runtime cost should be lower and determinism
	 * greater.
	 */

	std::map<SystemCallNr, SystemCallPtr> m_map;
};

} // end ns
