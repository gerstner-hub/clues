// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/strings.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string StringData::str() const {
	if (m_str.empty() && !isZero()) {
		return "<invalid>";
	}
	return cosmos::sprintf("\"%s\"", m_str.c_str());
}

void StringData::fetch(const Tracee &proc) {
	// fetch the the string from the Tracee's address space.
	proc.readString(asPtr(), m_str);
}

void StringArrayData::processValue(const Tracee &proc) {
	if (m_call->is32BitEmulationABI()) {
		/* in this case we have to be careful, the Tracee uses 4-byte
		 * pointers, while we are using 8-byte pointers */
		fetchPointers<uint32_t>(proc);
		return;
	}

	fetchPointers<uintptr_t>(proc);
}

template <typename PTR>
void StringArrayData::fetchPointers(const Tracee &proc) {
	const auto array_start = asPtr();
	std::vector<PTR> string_addrs;
	m_strs.clear();

	if (array_start == ForeignPtr::NO_POINTER)
		return;

	// first read in all start adresses of the c-strings for the string array
	proc.readVector(array_start, string_addrs);

	for (const auto &addr: string_addrs) {
		m_strs.push_back(std::string{});
		proc.readString(ForeignPtr{addr}, m_strs.back());
	}
}

std::string StringArrayData::str() const {

	if (m_strs.empty()) {
		if (isZero()) {
			return "NULL";
		} else {
			// pointer to no arguments
			return "[]";
		}
	}

	std::string ret;
	ret += "[";

	for (const auto &str: m_strs) {
		ret += "\"";
		ret += str;
		ret += "\", ";
	}

	if (!m_strs.empty())
		ret.erase(ret.size() - 2);

	ret += "]";

	return ret;
}

} // end ns
