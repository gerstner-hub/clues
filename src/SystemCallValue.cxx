// C++
#include <ostream>

// clues
#include <clues/SystemCallValue.hxx>

namespace clues {

void SystemCallValue::fill(const Tracee &proc, const RegisterSet::Word word) {
	m_val = word;
	processValue(proc);
}

std::string SystemCallValue::str() const {
	// by default simply return the register value as a string
	return std::to_string(m_val);
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCallValue &value) {
	o << value.longName() << " = " << value.str();
	return o;
}

