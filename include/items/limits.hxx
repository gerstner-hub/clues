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
