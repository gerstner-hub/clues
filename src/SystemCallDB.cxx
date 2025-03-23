// clues
#include <clues/SystemCallDB.hxx>

namespace clues {

SystemCall& SystemCallDB::get(const SystemCallNr nr) {
	if (auto it = m_map.find(nr); it != m_map.end()) {
		return *(it->second);
	} else {
		auto res = m_map.insert(std::make_pair(nr, create_syscall(nr)));

		it = res.first;
		return *(it->second);
	}
}

} // end ns
