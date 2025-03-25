#pragma once

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// The code parameter to the arch_prctl system call.
class CLUES_API ArchCodeParameter :
		public ValueInParameter {
public:
	explicit ArchCodeParameter() :
			ValueInParameter{"subfunction"} {
	}

	std::string str() const override;
};

} // end ns
