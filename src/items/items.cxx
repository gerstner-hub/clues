// C++
#include <sstream>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	if (auto ptr = valueAs<long*>(); ptr) {
		ss << ptr;
	} else {
		ss << "NULL";
	}
	return ss.str();
}

} // end ns
