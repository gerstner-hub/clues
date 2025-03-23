#pragma once

// C++
#include <optional>
#include <vector>

// Linux
#include <sys/stat.h>
#include <sys/resource.h>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/items/ErrnoResult.hxx>
#include <clues/items/files.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/items/time.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/SystemCallItem.hxx>

/*
 * Various specializations of SystemCallItem are found in this header
 */

namespace clues::item {

/*
 * TODO: support to get the length of the data area from a context-sensitive
 * sibling parameter and then print out the binary/ascii data as appropriate
 */
class CLUES_API GenericPointerValue :
		public PointerValue {
public: // functions

	explicit GenericPointerValue(
		const char *short_name,
		const char *long_name = nullptr,
		const Type type = Type::PARAM_IN) :
			PointerValue{type, short_name, long_name} {
	}

	std::string str() const override;

protected: // data

	void processValue(const Tracee &) override {}
	void updateData(const Tracee &) override {}
};

/// The code parameter to the arch_prctl system call.
class CLUES_API ArchCodeParameter :
		public ValueInParameter {
public:
	explicit ArchCodeParameter() :
			ValueInParameter{"subfunction"} {
	}

	std::string str() const override;
};

/// Memory protection used e.g. in mprotect().
class MemoryProtectionParameter :
		public ValueInParameter {
public: // data

	explicit MemoryProtectionParameter() :
			ValueInParameter{"prot", "protection"} {
	}

	std::string str() const override;
};

/// The futex operation to be performed in the context of a futex system call.
class CLUES_API FutexOperation :
		public ValueInParameter {
public: // functions
	explicit FutexOperation() :
			ValueInParameter{"op", "futex operation"} {
	}

	std::string str() const override;
};

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
		public PointerOutValue {
public: // functions
	explicit ResourceLimit() :
			PointerOutValue{"limit"} {
	}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct rlimit> m_limit;
};

} // end ns
