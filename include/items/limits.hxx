#pragma once

// Linux
#include <sys/resource.h>

// C++
#include <optional>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// A resource kind specification as used in getrlimit & friends.
class CLUES_API ResourceType :
		public ValueInParameter {
public: // functions
	explicit ResourceType() :
			ValueInParameter{"resource", "resource type"} {
	}

	std::string str() const override;
};

class CLUES_API ResourceLimit :
		public PointerValue {
public: // functions
	explicit ResourceLimit(const ItemType type) :
			PointerValue{type, "limit", ""} {
	}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

	void processValue(const Tracee &proc) override {
		// the same logic on input as on output
		return updateData(proc);
	}

	/// Checks whether the current context involves a 32-bit struct rlimit.
	/**
	 * On older 32-bit ABIs like I386, `getrlimit()` and `setrlimit()` use
	 * `struct compat_rlimit` in the kernel, with only 32-bit unsigned
	 * integer members.
	 **/
	bool isCompatSyscall() const;

protected: // data

	std::optional<struct rlimit> m_limit;
};

} // end ns
