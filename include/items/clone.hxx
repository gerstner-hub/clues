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

} // end ns
