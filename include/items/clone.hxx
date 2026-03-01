#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/proc/clone.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

class CLUES_API CloneFlagsValue :
			public SystemCallItem {
public: // functions

	explicit CloneFlagsValue() :
			SystemCallItem{ItemType::PARAM_IN, "flags", "clone flags"} {
	}

	std::string str() const override;

	cosmos::CloneFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::CloneFlags m_flags;
	/// For clone() 1/2 this contains the child exit signal, which is additionally encoded in the flags.
	std::optional<cosmos::SignalNr> exit_signal;
};

/// Structure used in clone3().
class CloneArgs :
		public SystemCallItem {
public: // functions

	explicit CloneArgs() :
			SystemCallItem{ItemType::PARAM_IN_OUT, "cl_args", "clone arguments"} {

	}

	/// Returns an optional containing the cosmos::CloneArgs structure, if available.
	/**
	 * \warning The returned structure is unaware that the contained
	 * pointers are for the Tracee, not the calling process. This means
	 * dereferencing any pointers in the structure will lead to memory
	 * issues.
	 **/
	const std::optional<cosmos::CloneArgs>& args() const {
		return m_args;
	}

	/// Return the newly created PIDFD.
	/**
	 * If CLONE_PIDFD was set in flags then this returns the resulting
	 * PIDFD assigned by the kernel. FileNum::INVALID otherwise.
	 **/
	cosmos::FileNum pidfd() const {
		return m_pidfd;
	}

	/// Return the cgroup2 file descriptor for the child to be placed in.
	/**
	 * If CLONE_INTO_CGROUP was set in flags then this returns the cgroup2
	 * file descriptor into which the child is to be placed by the kernel.
	 * FileNum::INVALID otherwise.
	 **/
	cosmos::FileNum cgroup2fd() const {
		return m_cgroup2_fd;
	}

	/// Return the new child's ThreadID stored in parent's memory.
	/**
	 * If PARENT_SETTID was set in flags then this returns the child's
	 * thread ID stored at the location specified by `parent_tid`.
	 * ThreadID::INVALID otherwise.
	 **/
	cosmos::ThreadID tid() const {
		return m_child_tid;
	}

	std::string str() const override;

	void processValue(const Tracee&) override;

	void updateData(const Tracee &proc) override;

protected: // functions

	bool verifySize() const;

	void resetArgs();

protected: // data

	std::optional<cosmos::CloneArgs> m_args;
	cosmos::FileNum m_pidfd = cosmos::FileNum::INVALID;
	cosmos::FileNum m_cgroup2_fd = cosmos::FileNum::INVALID;
	cosmos::ThreadID m_child_tid = cosmos::ThreadID::INVALID;
	std::vector<cosmos::ThreadID> m_tid_array;
};

} // end ns
