#pragma once

// Linux
#include <sys/prctl.h>
#include <sys/wait.h>

// C++
#include <optional>

// cosmos
#include <cosmos/proc/ProcessFile.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/proc/ResourceUsage.hxx>
#include <cosmos/proc/types.hxx>
#include <cosmos/thread/thread.hxx>

// clues
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

class ProcessID :
		public SystemCallItem {
public: // functions

	explicit ProcessID(const ItemCfg &cfg = ItemCfg{}) :
			SystemCallItem{
				cfg.type.value_or(ItemType::PARAM_IN),
				cfg.label.value_or("pid"),
				cfg.desc.value_or("process ID")} {
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

class ProcessGroupID :
		public SystemCallItem {
public: // functions

	explicit ProcessGroupID(const ItemCfg &cfg = ItemCfg{}) :
			SystemCallItem{
				cfg.type.value_or(ItemType::PARAM_IN),
				cfg.label.value_or("pgid"),
				cfg.desc.value_or("process group ID")} {
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

class SessionID :
		public SystemCallItem {
public: // functions

	explicit SessionID(const ItemCfg &cfg = ItemCfg{}) :
			SystemCallItem{
				cfg.type.value_or(ItemType::PARAM_IN),
				cfg.label.value_or("sid"),
				cfg.desc.value_or("session ID")} {
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

class ThreadID :
		public SystemCallItem {
public: // functions

	explicit ThreadID(const ItemCfg &cfg = ItemCfg{}) :
		SystemCallItem{
			cfg.type.value_or(ItemType::PARAM_IN),
			cfg.label.value_or("tid"),
			cfg.desc.value_or("thread ID")} {
	}

	auto tid() const { return m_tid; }

protected: // functions

	void processValue(const Tracee&) override {
		m_tid = valueAs<cosmos::ThreadID>();
	}

protected: // data

	cosmos::ThreadID m_tid = cosmos::ThreadID::INVALID;
};

class ExitStatus :
		public SystemCallItem {
public: // functions

	explicit ExitStatus(const ItemCfg &cfg = {}) :
			SystemCallItem{*cfg.type, cfg.label.value_or("status"), cfg.desc.value_or("")} {
	}

	auto status() const { return m_status; }

protected: // functions

	void processValue(const Tracee&) override {
		m_status = valueAs<cosmos::ExitStatus>();
	}

protected: // data

	cosmos::ExitStatus m_status = cosmos::ExitStatus::INVALID;
};

class WaitOptions :
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
class ResourceUsage :
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
class WaitStatus :
		public PointerToScalar<int> {
public: // functions

	explicit WaitStatus() :
			PointerToScalar{make_item_cfg("wstatus", "wait status")} {
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

	void updateData(const Tracee &tracee) override;

protected: // data

	std::optional<cosmos::WaitStatus> m_status;
};

/// Wait ID type used with WaitIDSystemCall.
class WaitID :
		public ValueInParameter {
public: // types

	enum class Type : std::underlying_type<idtype_t>::type {
		PID   = P_PID,
		PIDFD = P_PIDFD,
		PGID  = P_PGID,
		ALL   = P_ALL
	};

	using enum Type;

public: // functions

	explicit WaitID() :
			ValueInParameter{"idtype", "wait ID type"} {
	}

	Type type() const {
		return m_type;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Type m_type{0};
};

class PIDFDOpenFlags :
		public ValueInParameter {
public: // types

	using Flags = cosmos::ProcessFile::OpenFlags;
	using enum cosmos::ProcessFile::OpenFlag;

public: // functions

	explicit PIDFDOpenFlags() :
			ValueInParameter{"flags", "pidfd open flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Flags m_flags{0};
};

class PIDFDGetFDFlags :
	public ValueInParameter {
public: // types

	/* no flags defined yet */
	enum class Flag : int {
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit PIDFDGetFDFlags() :
			ValueInParameter{"flags", "open flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_flags = valueAs<Flags>();
	}

protected: // data

	Flags m_flags{0};
};

class PIDFDSendSignalFlags :
	public ValueInParameter {
public: // types

	using enum cosmos::signal::SendFlag;

	using Flags = cosmos::signal::SendFlags;

public: // functions

	explicit PIDFDSendSignalFlags() :
			ValueInParameter{"flags", "signal scope flags"} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &) override {
		m_flags = valueAs<Flags>();
	}

protected: // data

	Flags m_flags{0};
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
