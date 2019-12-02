#ifndef TUXTRACE_SIGNAL_HXX
#define TUXTRACE_SIGNAL_HXX

// C++
#include <iosfwd>
#include <string>

// Linux

namespace tuxtrace
{

/**
 * \brief
 * 	Represents a POSIX signal
 **/
class Signal
{
public: // types
	
	//! the basic signal type
	typedef int Type;

public: // functions
	
	explicit Signal(const Type &sig) : m_sig(sig) {}

	Signal& operator=(const Signal &o) { m_sig = o.m_sig; return *this; }
	
	const Type& raw() const { return m_sig; }

	std::string name() const;

protected: // data

	//! the raw signal
	Type m_sig;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const tuxtrace::Signal &sig);

#endif // inc. guard

