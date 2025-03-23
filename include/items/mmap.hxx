#pragma once

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// Memory protection used e.g. in mprotect().
class MemoryProtectionParameter :
		public ValueInParameter {
public: // data

	explicit MemoryProtectionParameter() :
			ValueInParameter{"prot", "protection"} {
	}

	std::string str() const override;
};

} // end ns
