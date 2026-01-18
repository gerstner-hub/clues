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

SystemCallItem unused = SystemCallItem{ItemType::PARAM_IN, "unused", "unused parameter"};

} // end ns
