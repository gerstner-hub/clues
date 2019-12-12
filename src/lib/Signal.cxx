// C++
#include <ostream>

// clues
#include "clues/Signal.hxx"
#include "clues/errors/ApiError.hxx"

// Linux
#include <signal.h>
#include <string.h>

namespace clues
{

std::string Signal::name() const
{
	return strsignal(m_sig);
}

void Signal::raiseSignal(const Signal &s)
{
	if( ::raise( s.raw() ) )
	{
		clues_throw( ApiError() );
	}
}

void Signal::sendSignal(const ProcessID &proc, const Signal &s)
{
	if( ::kill( proc, s.raw() ) )
	{
		clues_throw( ApiError() );
	}
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Signal &sig)
{
	o << sig.name() << " (" << sig.raw() << ")";

	return o;
}

