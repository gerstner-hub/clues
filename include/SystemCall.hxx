#pragma once

// C++
#include <iosfwd>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

// cosmos
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/ErrnoResult.hxx>
#include <clues/items/error.hxx>
#include <clues/sysnrs/fwd.hxx>
#include <clues/types.hxx>

namespace clues {
	class SystemCall;
	class Tracee;
}

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc);

namespace clues {

class SystemCallItem;
using SystemCallPtr = std::shared_ptr<SystemCall>;
using SystemCallItemPtr = std::shared_ptr<SystemCallItem>;

/// Base class to represent system call properties.
/**
 * This type stores properties that are common to all system calls:
 * 
 * - the system call number.
 * - an ordered list of parameters the system call expects, represented
 *   by the abstract SystemCallItem base class.
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
	using ParameterVector = std::vector<SystemCallItemPtr>;

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
		ParameterVector &&pars,
		SystemCallItemPtr ret,
		std::optional<size_t> open_id_par = {},
		std::optional<size_t> close_fd_par = {}
	);

	virtual ~SystemCall() {}

	// mark as non-copyable
	SystemCall(const SystemCall &other) = delete;
	SystemCall& operator=(const SystemCall &other) = delete;

	/// Update the stored parameter values from the given tracee.
	/**
	 * The given tracee is about to start the system call in question.
	 * Introspect the parameter values and store them in the current
	 * object's ParameterVector.
	 **/
	void setEntryInfo(const Tracee &proc,
			const cosmos::ptrace::SyscallInfo::EntryInfo &info);

	/// Update possible out and return parameter values from the given tracee.
	/**
	 * The given tracee just finished the system call in question.
	 * Introspect the return value and update out or in-out parameters as
	 * applicable.
	 **/
	void setExitInfo(const Tracee &proc,
			const cosmos::ptrace::SyscallInfo::ExitInfo &info);

	void updateOpenFiles(FDInfoMap &map);

	/// Returns the system call's human readable name.
	std::string_view name() const { return m_name; }
	/// Returns the number of parameters for this system call.
	size_t numPars() const { return m_pars.size(); }
	/// Returns the system call table number for this system call.
	SystemCallNr callNr() const { return m_nr; }

	/// Access to the parameters associated with this system call.
	const ParameterVector& parameters() const { return m_pars; }
	/// Access to the return value parameter associated with this system call.
	const SystemCallItemPtr result() const { return hasResultValue() ? m_return : nullptr; }
	/// Access to the errno result seen for this system call.
	std::optional<ErrnoResult> error() const { return m_error; }

	bool hasOutParameter() const;

	bool hasResultValue() const {
		return m_error == std::nullopt;
	}

	bool hasErrorCode() const {
		return !hasResultValue();
	}

	/// Returns the name of the given system call or "<unknown>" if unknown.
	/**
	 * The returned string has static storage duration.
	 **/
	static const char* name(const SystemCallNr nr);

	/// Returns whether the given system call number is in a valid range.
	static bool validNr(const SystemCallNr nr);

protected: // data

	/// The raw system call number of the system call.
	SystemCallNr m_nr;
	/// The basic name of the system call.
	const std::string_view m_name;;
	/// The return value of the system call.
	SystemCallItemPtr m_return;
	/// If the system call fails, this is the error code.
	std::optional<ErrnoResult> m_error;
	/// The array of system call parameters, if any.
	ParameterVector m_pars;
	/// if this is an open-like system call, then this gives the number of the parameter that contains the open identifier.
	const std::optional<size_t> m_open_id_par;
	/// If this is a close-like system call, then this gives the number of the parameter that contains the open file descriptor.
	const std::optional<size_t> m_close_fd_par;
};

/// Creates a dynamically allocated SystemCall instance for the given system call number
CLUES_API SystemCallPtr create_syscall(const SystemCallNr nr);

} // end ns
