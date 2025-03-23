// C++
#include <sstream>

// cosmos
#include <cosmos/proc/mman.hxx>

// clues
#include <clues/items/mmap.hxx>

namespace clues::item {

std::string MemoryProtectionParameter::str() const {
	std::stringstream ss;

	using cosmos::mem::AccessFlag;
	const auto flags = cosmos::mem::AccessFlags{valueAs<AccessFlag>()};

	if (flags == cosmos::mem::AccessFlags{}) {
		ss << "PROT_NONE";
	} else {
		if (flags[AccessFlag::READ])
			ss << "PROT_READ|";
		if (flags[AccessFlag::WRITE])
			ss << "PROT_WRITE|";
		if (flags[AccessFlag::EXEC])
			ss << "PROT_EXEC";
		if (flags[AccessFlag::SEM])
			ss << "PROT_SEM";
		if (flags[AccessFlag::SAO])
			ss << "PROT_SAO";
	}

	auto ret = ss.str();

	if (ret.empty()) {
		ret = "???";
	} else if (ret.back() == '|') {
		ret.erase(ret.size() - 1);
	}

	return ret;
}

} // end ns
