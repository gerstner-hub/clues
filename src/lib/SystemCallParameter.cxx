// C++
#include <ostream>

// clues
#include "clues/SystemCallParameter.hxx"

namespace clues
{

void SystemCallParameter::set(
	const TracedProc &proc,
	const RegisterSet::Word word)
{
	m_val = word;
	enteredCall(proc);
}

std::string SystemCallParameter::str() const
{
	// by default simply return the register value as a string
	return std::to_string(m_val);
}

} // end ns

std::ostream& operator<<(
	std::ostream &o,
	const clues::SystemCallParameter &par)
{
	o << par.name() << " = " << par.str();
	return o;
}

