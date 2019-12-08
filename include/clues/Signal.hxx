#ifndef CLUES_SIGNAL_HXX
#define CLUES_SIGNAL_HXX

// C++
#include <iosfwd>
#include <string>

namespace clues
{

/**
 * \brief
 * 	Represents a POSIX signal number
 **/
class Signal
{
public: // types

	//! the basic signal type
	typedef int Type;

public: // functions

	//! Creates a Signal objects for the given primitive signal number
	explicit Signal(const Type &sig) : m_sig(sig) {}

	Signal& operator=(const Signal &o) { m_sig = o.m_sig; return *this; }

	//! returns the primitive signal number stored in this object
	const Type& raw() const { return m_sig; }

	//! returns a human readable label for the currently stored signal
	//! number
	std::string name() const;

protected: // data

	//! the raw signal
	Type m_sig = 0;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Signal &sig);

#endif // inc. guard

