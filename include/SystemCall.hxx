#pragma once

// C++
#include <iosfwd>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

// cosmos
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/ErrnoResult.hxx>
#include <clues/items/error.hxx>
#include <clues/sysnrs/fwd.hxx>
#include <clues/types.hxx>

namespace clues {
	class SystemCall;
	class SystemCallInfo;
	class Tracee;
}

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc);

namespace clues {

class SystemCallItem;
using SystemCallPtr = std::shared_ptr<SystemCall>;
using SystemCallItemPtr = SystemCallItem*;

/// Access to System Call Data
/**
 * This type stores properties that are common to all system calls:
 *
 * - the system call number.
 * - an ordered list of parameters the system call expects, represented
 *   by the abstract SystemCallItem base class.
 * - a human readable name to identify the system call.
 *
 * The stream output operator<< allows to generically output information about
 * a system call.
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
	 * \param[in] pars
	 * 	A vector of the parameters in the order they need to be passed
	 * 	to the system call. The ownership is transferred to the
	 * 	SystemCall instance.
	 **/
	SystemCall(const SystemCallNr nr);

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
	void setEntryInfo(const Tracee &proc, const SystemCallInfo &info);

	/// Update possible out and return parameter values from the given tracee.
	/**
	 * The given tracee just finished the system call in question.
	 * Introspect the return value and update out or in-out parameters as
	 * applicable.
	 **/
	void setExitInfo(const Tracee &proc, const SystemCallInfo &info);

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
	SystemCallItemPtr result() const { return hasResultValue() ? m_return : nullptr; }
	/// Access to the errno result seen for this system call.
	std::optional<ErrnoResult> error() const { return m_error; }

	bool hasOutParameter() const;

	bool hasResultValue() const {
		return m_error == std::nullopt;
	}

	bool hasErrorCode() const {
		return !hasResultValue();
	}

	/// Returns the system call ABi seen during system call entry.
	ABI abi() const {
		return m_abi;
	}

	/// Returns the name of the given system call or "<unknown>" if unknown.
	/**
	 * The returned string has static storage duration.
	 **/
	static const char* name(const SystemCallNr nr);

	/// Returns whether the given system call number is in a valid range.
	static bool validNr(const SystemCallNr nr);

protected: // data

	void fillParameters(const Tracee &proc, const SystemCallInfo &info);

	/// Sets the return value system call item.
	/**
	 * A pointer to the return parameter definition for this syscall. The
	 * pointer ownership will be moved to the new SystemCall instance,
	 * i.e. it will be deleted during destruction of SystemCall. For
	 * system calls where there is no return value (exit), a synthetic
	 * parameter instance should be passed to avoid having to deal with
	 * the possibility of no return value existing.
	 **/
	void setReturnItem(SystemCallItem &ret) {
		m_return = &ret;
		m_return->setSystemCall(*this);
		if (!ret.isReturnValue()) {
			throw cosmos::RuntimeError{"added non-return-value as return item"};
		}
	}

	void setParameters() {}

	template <typename T, typename... Targs>
	void setParameters(T &par, Targs& ...rest) {
		par.setSystemCall(*this);
		m_pars.push_back(&par);
		setParameters(rest...);
	}

	/// Check whether a second pass needs to be made processing parameters.
	/**
	 * This function can be overridden by the actual system call
	 * implementation to perform context-sensitive evaluation of system
	 * call parameters (e.g. for `ioctl()` style system calls) upon system
	 * call entry..
	 *
	 * The implementation of this function is allowed to modify the amount
	 * and types of system call parameters and return parameter. In this
	 * case `true` must be returned to let the base class implementation
	 * reevaluate all system call parameters.
	 **/
	virtual bool check2ndPass() { return false; };

	/// Perform any necessary actions before processing a new system call entry event.
	virtual void prepareNewSystemCall() {}

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
	std::optional<size_t> m_open_id_par;
	/// If this is a close-like system call, then this gives the number of the parameter that contains the open file descriptor.
	std::optional<size_t> m_close_fd_par;
	/// The current system call ABI which is in effect.
	ABI m_abi = ABI::UNKNOWN;
};

/// Creates a dynamically allocated SystemCall instance for the given system call number
CLUES_API SystemCallPtr create_syscall(const SystemCallNr nr);

} // end ns
