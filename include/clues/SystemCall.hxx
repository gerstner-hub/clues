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

class SystemCallValue;

/**
 * \brief
 * 	Base class to represent system call properties
 * \details
 * 	This type stores all properties that are common to all system calls:
 *
 * 	- the system call number
 * 	- an ordered list of parameters the system call expects, represented
 * 	by the abstract SystemCallValue base class.
 * 	- a human readable name to identify the system call
 *
 * 	The actual derived type knows all about the individual system call
 * 	parameters and type of return value etc.
 *
 * 	Also the stream output operator<< allows to generically output
 * 	information about a system call.
 **/
class CLUES_API SystemCall
{
	friend std::ostream& ::operator<<(std::ostream&, const SystemCall&);
public: // types

	//! vector of the required parameters for a system call
	typedef std::vector<SystemCallValue*> ParameterVector;

public: // functions

	/**
	 * \brief
	 * 	Instantiates a new SystemCall object with given properties
	 * \param[in] nr
	 *	The unique well-known number of this system call
	 * \param[in] name
	 * 	A friendly, human readable name for the system call. This is
	 * 	considered to be statically allocated literal string, that
	 * 	will not be freed.
	 * \param[in] ret
	 * 	If applicable, a pointer to the return parameter definition
	 * 	for this syscall. nullptr if there is no return value. The
	 * 	pointer ownership will be moved to the new SystemCall
	 * 	instance, i.e. it will be deleted during destruction of
	 * 	SystemCall.
	 * \param[in] pars
	 * 	A vector of the parameters in the order they need to be passed
	 * 	to the system call. The ownership moves into the SystemCall
	 * 	instance.
	 **/
	SystemCall(
		const SystemCallNr nr,
		const char *name,
		ParameterVector &&pars,
		SystemCallValue *ret = nullptr,
		const size_t open_id_par = SIZE_MAX,
		const size_t close_fd_par = SIZE_MAX
	);

	virtual ~SystemCall();

	/**
	 * \brief
	 * 	Update the stored parameter values from the given tracee
	 * \details
	 * 	The given tracee is about to start the system call in
	 * 	question. Introspect the parameter values and update them in
	 * 	the current syscall object's parameters.
	 **/
	void setEntryRegs(const TracedProc &proc, const RegisterSet &r);

	/**
	 * \brief
	 * 	Update possible out and return parameter values from the given
	 * 	tracee
	 * \details
	 * 	The given tracee just finished the system call in question.
	 * 	Introspect the return value and update out or in-out
	 * 	parameters as applicable.
	 **/
	void setExitRegs(const TracedProc &proc, const RegisterSet &r);

	void updateOpenFiles(DescriptorPathMapping &mapping);

	//! returns the system call's human readable name
	const char* name() const { return m_name; }
	//! returns the number of parameters for this system call
	size_t numPars() const { return m_pars.size(); }
	//! returns the system call table nr. for this system call
	SystemCallNr callNr() const { return m_nr; }

	//! access to the parameters associated with this system call
	const ParameterVector& parameters() const { return m_pars; }
	//! access to the return value parameter associated with this syscall
	const SystemCallValue& result() const { return *m_return; }

protected: // functions	

protected: // data

	//! the raw sytem call number we represent
	SystemCallNr m_nr;
	//! the basic name of the system call we're representing
	const char *m_name = nullptr;
	//! the return value type of the system call
	SystemCallValue *m_return = nullptr;
	//! the array of system call parameters, if any
	ParameterVector m_pars;
	//! if this is an open-like system call this gives the number of the
	//! parameter that contains the open identifier
	const size_t m_open_id_par;
	//! if this is a close-like system call this gives the number of the
	//! parameter that contains the open file descriptor
	const size_t m_close_fd_par;
};

} // end ns

#endif // inc. guard

