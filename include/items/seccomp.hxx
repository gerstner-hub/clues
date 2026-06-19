#pragma once

// C++
#include <vector>

// clues
#include <clues/items/items.hxx>
#include <clues/macros.h>

// Linux
#include <linux/filter.h>
#include <linux/seccomp.h>

namespace clues::item {


/// Secure computing mode enum.
/**
 * This is currently only used with prctl::SetSecCompSystemCall.
 **/
class CLUES_API SecCompMode :
		public ValueInParameter {
public: // types


	enum class Mode : long {
		/// Enter strict secure computing mode (see seccomp(2)).
		STRICT  = SECCOMP_MODE_STRICT,
		/// Only system called defined by a filter program are allowed.
		FILTER  = SECCOMP_MODE_FILTER,
	};

	using enum Mode;

public: // functions

	explicit SecCompMode() :
			ValueInParameter{"mode", "secure computing mode"} {
	}

	Mode mode() const {
		return m_mode;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Mode m_mode{};
};

/// A pointer to a `struct sock_fprog` containing a range of `struct sock_filter`.
/**
 * This is currently only used with the prctl::SetSecCompSystemCall.
 **/
class CLUES_API FilterProg :
		public PointerInValue {
public: // functions

	explicit FilterProg() :
			PointerInValue{"filter", "bpf filter program struct"} {
	}

	std::string str() const override;

	/// Provides access to the raw `struct sock_fprog` passed by the Tracee.
	/**
	 * In case no valid data could be read from the Tracee this returns
	 * nullptr. The pointer is only valid for the duration of the system
	 * call entry/exit stop of the related system call.
	 *
	 * The `filter` pointer, if any, in the returned structure points into
	 * tracee memory. For accessing the filter programs in the tracer use
	 * `filters()`.
	 **/
	const struct sock_fprog* prog() const {
		return m_prog ? &(*m_prog) : nullptr;
	}

	/// Provides access to the raw `struct sock_filter` programs.
	/**
	 * This item also fetches the filter program data from the tracee and
	 * stores it in a std::vector. In case no valid data could be read
	 * from the Tracee this returns an empty vector.
	 **/
	const std::vector<struct sock_filter>& filters() const {
		return m_filters;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	std::optional<struct sock_fprog> m_prog;
	std::vector<struct sock_filter> m_filters;
};

} // end ns
