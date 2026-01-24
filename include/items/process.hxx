#pragma once

// cosmos
#include <cosmos/proc/types.hxx>
#include <cosmos/thread/thread.hxx>

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

class ThreadIDItem :
		public SystemCallItem {
public: // functions

	explicit ThreadIDItem(const ItemType type, const std::string_view desc) :
			SystemCallItem{type, "tid", desc} {
	}

	auto tid() const { return m_tid; }

protected: // functions

	void processValue(const Tracee&) override {
		m_tid = valueAs<cosmos::ThreadID>();
	}

protected: // data

	cosmos::ThreadID m_tid = cosmos::ThreadID::INVALID;
};

class ExitStatusItem :
		public SystemCallItem {
public: // functions

	explicit ExitStatusItem(const ItemType type, const std::string_view desc) :
			SystemCallItem{type, "status", desc} {
	}

	auto status() const { return m_status; }

protected: // fnctions

	void processValue(const Tracee&) override {
		m_status = valueAs<cosmos::ExitStatus>();
	}

protected: // data

	cosmos::ExitStatus m_status = cosmos::ExitStatus::INVALID;
};

} // end ns
