#ifndef TUXTRACE_SYSTEMCALL_HXX
#define TUXTRACE_SYSTEMCALL_HXX

// C++
#include <iosfwd>
#include <map>
#include <string>
#include <vector>
#include <utility>

// Linux

// tuxtrace
#include <tuxtrace/include/RegisterSet.hxx>

namespace tuxtrace
{
	class SystemCall;
	class TracedProc;
}

std::ostream& operator<<(std::ostream &o, const tuxtrace::SystemCall &sc);

namespace tuxtrace
{


//! a system call table number
typedef RegisterSet::Word SystemCallNr;

class SystemCallParameter;

/**
 * \brief
 * 	Base class for all kinds of different system call instances
 * \details
 * 	This type stores all properties that are common to all system calls:
 *
 * 	- the system call nr.
 * 	- the number of parameters the system call takes
 * 	- a human readable name to identify the system call
 *
 * 	The actual instance type SystemCall knows all about the individual
 * 	system call parameters and type of return value etc.
 *
 * 	Also a virtual print() function allows to generically assemble
 * 	information about a system call
 **/
class SystemCall
{
	friend std::ostream& ::operator<<(std::ostream&, const SystemCall&);
public: // types

	//! vector of the required parameters for a system call
	typedef std::vector<SystemCallParameter*> ParameterVector;

public: // functions

	SystemCall(
		const SystemCallNr nr,
		const char *name,
		SystemCallParameter *ret,
		ParameterVector &&pars);

	~SystemCall();

	void setEntryRegs(const TracedProc &proc, const RegisterSet &r);
	void setExitRegs(const TracedProc &proc, const RegisterSet &r);

	//! returns the system call's name
	const char* name() const { return m_name; }
	//! returns the number of parameters for this system call
	size_t numPars() const { return m_pars.size(); }
	//! returns the system call table nr. for this system call
	SystemCallNr callNr() const { return m_nr; }

	//! access to the parameters associated with this system call
	const ParameterVector& parameters() const { return m_pars; }
	//! access to the return value parameter associated with this sys. c.
	const SystemCallParameter& result() const { return *m_return; }
	
protected: // functions	
	
protected:

	//! the raw sytem call number we represent
	SystemCallNr m_nr;
	//! the basic name of the system call we're representing
	const char *m_name;
	//! the return value type of the system call
	SystemCallParameter *m_return;
	//! the array of system call parameters, if any
	ParameterVector m_pars;
};

} // end ns

#endif // inc. guard

