// C++
#include <ostream>

// clues
#include "clues/Signal.hxx"

// Linux
#include <string.h>

namespace clues
{

std::string Signal::name() const
{
	return strsignal(m_sig);
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Signal &sig)
{
	o << sig.name() << " (" << sig.raw() << ")";

	return o;
}

