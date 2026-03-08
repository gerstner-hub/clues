#pragma once

// Linux
#include <fcntl.h>

// C++
#include <optional>

// cosmos
#include <cosmos/BitMask.hxx>

// clues
#include <clues/items/fcntl.hxx>
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/types.hxx>

namespace clues::item {

/// Pointer to pipefd[2] array in pipe() system calls.
class CLUES_API PipeEnds :
		public PointerOutValue {
public: // functions

	explicit PipeEnds() :
			PointerOutValue{"pipefd", "pointer to array pipefd[2]"} {
	}

	std::string str() const override;

	cosmos::FileNum readEnd() const {
		return m_read_end;
	}

	cosmos::FileNum writeEnd() const {
		return m_write_end;
	}

	/// Returns whether valid read and write end file numbers are stored.
	/**
	 * On failed system calls or sudden Tracee death these can have
	 * invalid values.
	 **/
	bool haveEnds() const {
		return m_read_end != cosmos::FileNum::INVALID && m_write_end != cosmos::FileNum::INVALID;
	}

protected: // functions

	void reset() {
		m_read_end = cosmos::FileNum::INVALID;
		m_write_end = cosmos::FileNum::INVALID;
	}

	void processValue(const Tracee &proc) override;

protected: // data

	cosmos::FileNum m_read_end = cosmos::FileNum::INVALID;
	cosmos::FileNum m_write_end = cosmos::FileNum::INVALID;
};

/// Flags used in Pipe2SystemCall.
class CLUES_API PipeFlags :
		public ValueInParameter {
public: // types

	enum class Flag : int {
		CLOEXEC           = O_CLOEXEC,
		DIRECT            = O_DIRECT,
		NONBLOCK          = O_NONBLOCK,
		NOTIFICATION_PIPE = O_EXCL /* this constant seems only defined in kernel headers and is just a reused O_EXCL */
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit PipeFlags() :
			ValueInParameter{"flags"} {
	}

	std::optional<Flags> flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<Flags> m_flags;
};

} // end ns

