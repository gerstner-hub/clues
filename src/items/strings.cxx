// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/strings.hxx>
#include <clues/Tracee.hxx>

namespace clues::item {

std::string StringData::str() const {
	return cosmos::sprintf("\"%s\"", m_str.c_str());
}

void StringData::fetch(const Tracee &proc) {
	// the address of the string in the userspace address space
	const auto addr = valueAs<long*>();
	proc.readString(addr, m_str);
}

void StringArrayData::processValue(const Tracee &proc) {
	const auto array_start = valueAs<long*>();
	std::vector<long*> string_addrs;
	m_strs.clear();

	if (!array_start)
		return;

	// first read in all start adresses of the c-strings for the string array
	proc.readVector(array_start, string_addrs);

	for (const auto &addr: string_addrs) {
		m_strs.push_back(std::string{});
		proc.readString(addr, m_strs.back());
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
