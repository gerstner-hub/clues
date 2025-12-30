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

std::string IntValue::str() const {
	return std::to_string(m_value);
}

} // end ns
