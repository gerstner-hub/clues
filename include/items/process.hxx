#pragma once

// cosmos
#include <cosmos/proc/types.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

class ProcessIDItem :
		public SystemCallItem {
public: // functions

	explicit ProcessIDItem(const ItemType type, const std::string_view desc) :
			SystemCallItem{type, "pid", desc} {
	}

	auto pid() const { return m_pid; }

protected: // functions

	void processValue(const Tracee&) override {
		m_pid = valueAs<cosmos::ProcessID>();
	}

protected: // data

	cosmos::ProcessID m_pid = cosmos::ProcessID::INVALID;
};

} // end ns
