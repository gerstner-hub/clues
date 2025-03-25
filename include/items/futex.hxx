#pragma once

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// The futex operation to be performed in the context of a futex system call.
class CLUES_API FutexOperation :
		public ValueInParameter {
public: // functions
	explicit FutexOperation() :
			ValueInParameter{"op", "futex operation"} {
	}

	std::string str() const override;
};

} // end ns
