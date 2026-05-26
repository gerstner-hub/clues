#pragma once

// cosmos
#include <cosmos/proc/process.hxx>
#include <cosmos/proc/ResourceUsage.hxx>
#include <cosmos/proc/types.hxx>
#include <cosmos/thread/thread.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

class CLUES_API ProcessID :
		public SystemCallItem {
public: // functions

	explicit ProcessID(const ItemType type, const std::string_view desc = "process ID") :
			SystemCallItem{type, "pid", desc} {
	}

	ProcessID(const ItemType type, const std::string_view label, const std::string_view desc) :
			SystemCallItem{type, label, desc} {
	}

	auto pid() const { return m_pid; }

	std::string str() const override {
		if (m_pid == cosmos::ProcessID::INVALID)
			return "-1";

		return SystemCallItem::str();
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_pid = valueAs<cosmos::ProcessID>();
	}

protected: // data

	cosmos::ProcessID m_pid = cosmos::ProcessID::INVALID;
};

class CLUES_API ProcessGroupID :
		public SystemCallItem {
public: // functions

	explicit ProcessGroupID(const ItemType type, const std::string_view desc = "process group ID") :
			SystemCallItem{type, "pgid", desc} {
	}

	ProcessGroupID(const ItemType type, const std::string_view label, const std::string_view desc) :
			SystemCallItem{type, label, desc} {
	}

	auto pgid() const { return m_pgid; }

	std::string str() const override {
		if (m_pgid == cosmos::ProcessGroupID::INVALID)
			return "-1";

		return SystemCallItem::str();
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_pgid = valueAs<cosmos::ProcessGroupID>();
	}

protected: // data

	cosmos::ProcessGroupID m_pgid = cosmos::ProcessGroupID::INVALID;
};

class CLUES_API SessionID :
		public SystemCallItem {
public: // functions

	explicit SessionID(const ItemType type, const std::string_view desc = "session ID") :
			SystemCallItem{type, "sid", desc} {
	}

	SessionID(const ItemType type, const std::string_view label, const std::string_view desc) :
			SystemCallItem{type, label, desc} {
	}

	auto sid() const { return m_sid; }

	std::string str() const override {
		if (m_sid == cosmos::SessionID::INVALID)
			return "-1";

		return SystemCallItem::str();
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_sid = valueAs<cosmos::SessionID>();
	}

protected: // data

	cosmos::SessionID m_sid = cosmos::SessionID::INVALID;
};

class CLUES_API ThreadID :
		public SystemCallItem {
public: // functions

	explicit ThreadID(const ItemType type, const std::string_view desc = "thread ID") :
			SystemCallItem{type, "tid", desc} {
	}

	ThreadID(const ItemType type, const std::string_view label, const std::string_view desc) :
			SystemCallItem{type, label, desc} {
	}

	auto tid() const { return m_tid; }

protected: // functions

	void processValue(const Tracee&) override {
		m_tid = valueAs<cosmos::ThreadID>();
	}

protected: // data

	cosmos::ThreadID m_tid = cosmos::ThreadID::INVALID;
};

class CLUES_API ExitStatus :
		public SystemCallItem {
public: // functions

	explicit ExitStatus(const ItemType type, const std::string_view desc) :
			SystemCallItem{type, "status", desc} {
	}

	auto status() const { return m_status; }

protected: // functions

	void processValue(const Tracee&) override {
		m_status = valueAs<cosmos::ExitStatus>();
	}

protected: // data

	cosmos::ExitStatus m_status = cosmos::ExitStatus::INVALID;
};

class CLUES_API WaitOptions :
		public ValueInParameter {
public: // functions

	explicit WaitOptions() :
			ValueInParameter{"options", "wait options"} {
	}

	auto options() const {
		return m_options;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override {
		m_options = cosmos::WaitFlags{valueAs<int>()};
	}

protected: // data

	cosmos::WaitFlags m_options;
};

/// Pointer to a `struct rusage` to be filled in.
class CLUES_API ResourceUsage :
		public PointerOutValue {
public: // functions

	explicit ResourceUsage() :
			PointerOutValue{"rusage", "resource usage"} {
	}

	std::string str() const override;

	std::optional<const cosmos::ResourceUsage> usage() const {
		if (!m_rusage)
			return {};
		return *m_rusage;
	}

protected: // types

	struct Usage :
			public cosmos::ResourceUsage {

		struct rusage& raw() {
			return m_ru;
		}

		using cosmos::ResourceUsage::raw;
	};

protected: // functions

	void processValue(const Tracee &) override {
		m_rusage.reset();
	}

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<Usage> m_rusage;
};

/// Pointer to an int containing wait() status result data.
class CLUES_API WaitStatus :
		public PointerToScalar<int> {
public: // functions

	explicit WaitStatus() :
			PointerToScalar{"wstatus", "wait status"} {
	}

	const std::optional<cosmos::WaitStatus>& status() const {
		return m_status;
	}

protected: // functions

	std::string scalarToString() const override;

	void processValue(const Tracee &tracee) override {
		m_status.reset();
		PointerToScalar<int>::processValue(tracee);
	}

	void updateData(const Tracee &tracee) override {
		PointerToScalar<int>::updateData(tracee);
		if (m_val) {
			m_status = cosmos::WaitStatus{*m_val};
		}
	}

protected: // data

	std::optional<cosmos::WaitStatus> m_status;
};

} // end ns
