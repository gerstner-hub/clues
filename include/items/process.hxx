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

class ProcessIDItem :
		public SystemCallItem {
public: // functions

	explicit ProcessIDItem(const ItemType type, const std::string_view desc) :
			SystemCallItem{type, "pid", desc} {
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

class ThreadIDItem :
		public SystemCallItem {
public: // functions

	explicit ThreadIDItem(const ItemType type, const std::string_view desc = "thread id") :
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

protected: // functions

	void processValue(const Tracee&) override {
		m_status = valueAs<cosmos::ExitStatus>();
	}

protected: // data

	cosmos::ExitStatus m_status = cosmos::ExitStatus::INVALID;
};

class WaitOptionsItem :
		public ValueInParameter {
public: // functions

	explicit WaitOptionsItem() :
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
class CLUES_API ResourceUsageItem :
		public PointerOutValue {
public: // functions

	ResourceUsageItem() :
			PointerOutValue{"rusage", "resource usage"} {
	}

	std::string str() const override;

protected: // types

	struct ResourceUsage :
			public cosmos::ResourceUsage {

		struct rusage& raw() {
			return m_ru;
		}

		using cosmos::ResourceUsage::raw;
	};

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<ResourceUsage> m_rusage;
};

/// Pointer to an int containing wait() status result data.
class CLUES_API WaitStatusItem :
		public PointerToScalar<int> {
public: // functions

	explicit WaitStatusItem() :
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
