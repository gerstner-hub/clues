#pragma once

// Linux
#include <sys/resource.h>

// C++
#include <limits>
#include <optional>

// cosmos
#include <cosmos/proc/limits.hxx>

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

	cosmos::LimitType type() const {
		return m_limit;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	cosmos::LimitType m_limit = cosmos::LimitType{std::numeric_limits<int>::max()};
};

class CLUES_API ResourceLimit :
		public PointerValue {
public: // functions
	explicit ResourceLimit(const ItemType type, const std::string_view name = {}) :
			PointerValue{type, name.empty() ? "limit" : name, ""} {
	}

	std::string str() const override;

	std::optional<cosmos::LimitSpec> limit() const {
		return m_limit;
	}

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

	std::optional<cosmos::LimitSpec> m_limit;
};

} // end ns
