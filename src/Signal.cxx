// C++
#include <ostream>

// tuxtrace
#include <tuxtrace/include/Signal.hxx>

// Linux
#include <string.h>

namespace tuxtrace
{

std::string Signal::name() const
{
	return strsignal(m_sig);
}

} // end ns

std::ostream& operator<<(std::ostream &o, const tuxtrace::Signal &sig)
{
	o << sig.name() << " (" << sig.raw() << ")";

	return o;
}

