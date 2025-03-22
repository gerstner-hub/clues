// C++
#include <ostream>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues {

void SystemCallItem::fill(const Tracee &proc, const Word word) {
	m_val = word;
	processValue(proc);
}

std::string SystemCallItem::str() const {
	// by default simply return the register value as a string
	return std::to_string(cosmos::to_integral(m_val));
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCallItem &value) {
	o << value.longName() << " = " << value.str();
	return o;
}

