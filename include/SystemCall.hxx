#pragma once

// C++
#include <iosfwd>
#include <string>
#include <utility>
#include <vector>

// clues
#include <clues/RegisterSet.hxx>
#include <clues/types.hxx>

namespace clues {
	class SystemCall;
	class Tracee;
}

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc);

namespace clues {

class SystemCallValue;

/// Base class to represent system call properties.
/**
 * This type stores properties that are common to all system calls:
 * 
 * - the system call number.
 * - an ordered list of parameters the system call expects, represented
 *   by the abstract SystemCallValue base class.
 * - a human readable name to identify the system call.
 * 
 * The actual derived type knows all about the individual system call
 * parameters and type of return value etc.
 * 
 * Also the stream output operator<< allows to generically output
 * information about a system call.
 **/
class CLUES_API SystemCall {
	friend std::ostream& ::operator<<(std::ostream&, const SystemCall&);
public: // types

	/// Vector of the parameters required for a system call.
	using ParameterVector = std::vector<SystemCallValue*>;

public: // functions

	/// Instantiates a new SystemCall object with given properties.
	/**
	 * \param[in] nr
	 *	The unique well-known number of this system call.
	 * \param[in] name
	 * 	A friendly, human readable name for the system call. This is
	 * 	considered to be statically allocated literal string, that
	 * 	will not be freed.
	 * \param[in] ret
	 * 	A pointer to the return parameter definition for this syscall.
	 * 	The pointer ownership will be moved to the new SystemCall
	 * 	instance, i.e. it will be deleted during destruction of
	 * 	SystemCall. For system calls where there is no return value
	 * 	(exit), a synthetic parameter instance should be passed to
	 * 	avoid having to deal with the possibility of no return value
	 * 	existing.
	 * \param[in] pars
	 * 	A vector of the parameters in the order they need to be passed
	 * 	to the system call. The ownership is transferred to the
	 * 	SystemCall instance.
	 **/
	SystemCall(
		const SystemCallNr nr,
		const char *name,
		ParameterVector &&pars,
		SystemCallValue *ret,
		const size_t open_id_par = SIZE_MAX,
		const size_t close_fd_par = SIZE_MAX
	);

	virtual ~SystemCall();

	// mark as non-copyable
	SystemCall(const SystemCall &other) = delete;
	SystemCall& operator=(const SystemCall &other) = delete;

	/// Update the stored parameter values from the given tracee.
	/**
	 * The given tracee is about to start the system call in question.
	 * Introspect the parameter values and store them in the current
	 * object's ParameterVector.
	 **/
	void setEntryRegs(const Tracee &proc, const RegisterSet &r);

	/// Update possible out and return parameter values from the given tracee.
	/**
	 * The given tracee just finished the system call in question.
	 * Introspect the return value and update out or in-out parameters as
	 * applicable.
	 **/
	void setExitRegs(const Tracee &proc, const RegisterSet &r);

	void updateOpenFiles(DescriptorPathMapping &mapping);

	/// Returns the system call's human readable name.
	const char* name() const { return m_name; }
	/// Returns the number of parameters for this system call.
	size_t numPars() const { return m_pars.size(); }
	/// Returns the system call table number for this system call.
	SystemCallNr callNr() const { return m_nr; }

	/// Access to the parameters associated with this system call
	const ParameterVector& parameters() const { return m_pars; }
	/// Access to the return value parameter associated with this syscall
	const SystemCallValue& result() const { return *m_return; }

protected: // data

	/// The raw system call number we represent.
	SystemCallNr m_nr;
	/// The basic name of the system call we're representing.
	const char *m_name = nullptr;
	/// The return value type of the system call, if any.
	SystemCallValue *m_return;
	/// The array of system call parameters, if any.
	ParameterVector m_pars;
	/// if this is an open-like system call, then this gives the number of the parameter that contains the open identifier.
	const size_t m_open_id_par;
	/// If this is a close-like system call, then this gives the number of the parameter that contains the open file descriptor.
	const size_t m_close_fd_par;
};

} // end ns
