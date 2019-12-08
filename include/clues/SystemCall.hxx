#ifndef CLUES_SYSTEMCALL_HXX
#define CLUES_SYSTEMCALL_HXX

// C++
#include <iosfwd>
#include <map>
#include <string>
#include <vector>
#include <utility>

// Linux

// clues
#include "clues/RegisterSet.hxx"
#include "clues/types.hxx"

namespace clues
{
	class SystemCall;
	class TracedProc;
}

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc);

namespace clues
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
		ParameterVector &&pars,
		const size_t open_id_par = SIZE_MAX,
		const size_t close_fd_par = SIZE_MAX);

	~SystemCall();

	void setEntryRegs(const TracedProc &proc, const RegisterSet &r);
	void setExitRegs(const TracedProc &proc, const RegisterSet &r);

	void updateOpenFiles(DescriptorPathMapping &mapping);

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
	//! if this is a open-like system call this gives the number of the
	//! parameter that contains the open identifier
	const size_t m_open_id_par;
	//! if this is a close-like system call this gives the number of the
	//! parameter that contains the open file descriptor
	const size_t m_close_fd_par;
};

} // end ns

#endif // inc. guard

