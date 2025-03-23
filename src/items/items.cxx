// C++
#include <sstream>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

std::string GenericPointerValue::str() const {
	std::stringstream ss;
	ss << valueAs<long*>();
	return ss.str();
}

} // end ns
