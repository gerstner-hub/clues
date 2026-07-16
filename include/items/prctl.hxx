#pragma once

// clues
#include <clues/arch.hxx>
#include <clues/items/items.hxx>
#include <clues/items/process.hxx>

// cosmos
#include <cosmos/proc/AuxVector.hxx>

// Linux
#ifdef CLUES_HAVE_ARCH_PRCTL
#	include <asm/prctl.h>
#endif
#include <linux/prctl.h>

namespace clues::item {

CLUES_DEFAULT_VISIBILITY_ON;

#ifdef CLUES_HAVE_ARCH_PRCTL
/// The `op` parameter to the arch_prctl system call.
class ArchOpParameter :
		public ValueInParameter {
public: // types

	enum class Operation : int {
		SET_CPUID = ARCH_SET_CPUID,
		GET_CPUID = ARCH_GET_CPUID,
		SET_FS    = ARCH_SET_FS,
		GET_FS    = ARCH_GET_FS,
		SET_GS    = ARCH_SET_GS,
		GET_GS    = ARCH_GET_GS
	};

public: // functions

	explicit ArchOpParameter() :
			ValueInParameter{ItemCfg{.label = "op"}} {
	}

	std::string str() const override;

	Operation operation() const {
		return m_op;
	}

protected: // functions

	void processValue(const Tracee &) override {
		m_op = Operation{valueAs<int>()};
	}

protected: // data

	Operation m_op = Operation{0};
};
#endif

/// An enum describing the concrete `prctl()` operation to be carried out.
class ProcessOp :
		public ValueInParameter {
public: // types

	/// The main operation of a prctl() system call.
	/**
	 * This is a strong enum wrapper around the PR_ constants used in
	 * `prctl()`.
	 **/
	enum class Operation : int {
		CAP_AMBIENT                = PR_CAP_AMBIENT,
		CAPBSET_READ               = PR_CAPBSET_READ,
		CAPBSET_DROP               = PR_CAPBSET_DROP,
		SET_CHILD_SUBREAPER        = PR_SET_CHILD_SUBREAPER,
		GET_CHILD_SUBREAPER        = PR_GET_CHILD_SUBREAPER,
		SET_DUMPABLE               = PR_SET_DUMPABLE,
		GET_DUMPABLE               = PR_GET_DUMPABLE,
		SET_ENDIAN                 = PR_SET_ENDIAN,
		GET_ENDIAN                 = PR_GET_ENDIAN,
		SET_FP_MODE                = PR_SET_FP_MODE,
		GET_FP_MODE                = PR_GET_FP_MODE,
		SET_FPEMU                  = PR_SET_FPEMU,
		GET_FPEMU                  = PR_GET_FPEMU,
		SET_FPEXC                  = PR_SET_FPEXC,
		GET_FPEXC                  = PR_GET_FPEXC,
		SET_IO_FLUSHER             = PR_SET_IO_FLUSHER,
		GET_IO_FLUSHER             = PR_GET_IO_FLUSHER,
		SET_KEEPCAPS               = PR_SET_KEEPCAPS,
		GET_KEEPCAPS               = PR_GET_KEEPCAPS,
		MCE_KILL                   = PR_MCE_KILL,
		MCE_KILL_GET               = PR_MCE_KILL_GET,
		SET_MM                     = PR_SET_MM,
		SET_VMA                    = PR_SET_VMA,
		MPX_ENABLE_MANAGEMENT      = PR_MPX_ENABLE_MANAGEMENT,
		MPX_DISABLE_MANAGEMENT     = PR_MPX_DISABLE_MANAGEMENT,
		SET_NAME                   = PR_SET_NAME,
		GET_NAME                   = PR_GET_NAME,
		SET_NO_NEW_PRIVS           = PR_SET_NO_NEW_PRIVS,
		GET_NO_NEW_PRIVS           = PR_GET_NO_NEW_PRIVS,
		PAC_RESET_KEYS             = PR_PAC_RESET_KEYS,
		SET_PDEATHSIG              = PR_SET_PDEATHSIG,
		GET_PDEATHSIG              = PR_GET_PDEATHSIG,
		SET_PTRACER                = PR_SET_PTRACER,
		SET_SECCOMP                = PR_SET_SECCOMP,
		GET_SECCOMP                = PR_GET_SECCOMP,
		SET_SECUREBITS             = PR_SET_SECUREBITS,
		GET_SECUREBITS             = PR_GET_SECUREBITS,
		GET_SPECULATION_CTRL       = PR_GET_SPECULATION_CTRL,
		SET_SPECULATION_CTRL       = PR_SET_SPECULATION_CTRL,
		SVE_SET_VL                 = PR_SVE_SET_VL,
		SVE_GET_VL                 = PR_SVE_GET_VL,
		SET_SYSCALL_USER_DISPATCH  = PR_SET_SYSCALL_USER_DISPATCH,
		SET_TAGGED_ADDR_CTRL       = PR_SET_TAGGED_ADDR_CTRL,
		GET_TAGGED_ADDR_CTRL       = PR_GET_TAGGED_ADDR_CTRL,
		TASK_PERF_EVENTS_DISABLE   = PR_TASK_PERF_EVENTS_DISABLE,
		TASK_PERF_EVENTS_ENABLE    = PR_TASK_PERF_EVENTS_ENABLE,
		SET_THP_DISABLE            = PR_SET_THP_DISABLE,
		GET_THP_DISABLE            = PR_GET_THP_DISABLE,
		GET_TID_ADDRESS            = PR_GET_TID_ADDRESS,
		SET_TIMERSLACK             = PR_SET_TIMERSLACK,
		GET_TIMERSLACK             = PR_GET_TIMERSLACK,
		SET_TIMING                 = PR_SET_TIMING,
		GET_TIMING                 = PR_GET_TIMING,
		SET_TSC                    = PR_SET_TSC,
		GET_TSC                    = PR_GET_TSC,
		SET_UNALIGN                = PR_SET_UNALIGN,
		GET_UNALIGN                = PR_GET_UNALIGN,
		GET_AUXV                   = PR_GET_AUXV,
		SET_MDWE                   = PR_SET_MDWE,
		GET_MDWE                   = PR_GET_MDWE,
		/* these are not yet available in some more recent Linux
		 * distros */
#ifdef PR_RISCV_SET_ICACHE_FLUSH_CTX
		RISCV_SET_ICACHE_FLUSH_CTX = PR_RISCV_SET_ICACHE_FLUSH_CTX,
#endif
#ifdef PR_FUTEX_HASH
		FUTEX_HASH                 = PR_FUTEX_HASH,
#endif
	};

	using enum Operation;

public: // functions

	ProcessOp() :
			ValueInParameter{make_item_cfg("op", "operation")} {
	}

	Operation operation() const {
		return m_op;
	}

	std::string str() const override;

	std::string_view label(const Operation op) const;

protected: // functions

	void processValue(const Tracee &tracee) override;

protected: // data

	Operation m_op{};
};

/// Sub-operation enum value for prctl(PR_CAP_AMBIENT, subop).
class AmbientCapOp :
		public ValueInParameter {
public: // types

	enum class Operation : long {
		RAISE     = PR_CAP_AMBIENT_RAISE,
		LOWER     = PR_CAP_AMBIENT_LOWER,
		IS_SET    = PR_CAP_AMBIENT_IS_SET,
		CLEAR_ALL = PR_CAP_AMBIENT_CLEAR_ALL,
	};

	using enum Operation;

public: // functions

	explicit AmbientCapOp() :
			ValueInParameter{make_item_cfg("subop",
					"ambient capability set operation")} {
	}

	Operation operation() const {
		return m_op;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Operation m_op{};
};

/// Sub-operation enum value for prctl(PR_MCE_KILL, subop).
class MachineCheckOp :
		public ValueInParameter {
public: // types

	enum class Operation : long {
		CLEAR = PR_MCE_KILL_CLEAR,
		SET   = PR_MCE_KILL_SET
	};

	using enum Operation;

public: // functions

	explicit MachineCheckOp() :
			ValueInParameter{make_item_cfg("subop",
					"machine check exception operation")} {
	}

	Operation operation() const {
		return m_op;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Operation m_op{};
};

/// Policy enum value for prctl(PR_MCE_KILL, PCR_ME_KILL_SET, policy).
class MachineCheckPolicy :
		public ValueParameter {
public: // types

	enum class Policy : long {
		KILL_EARLY = PR_MCE_KILL_EARLY,
		KILL_LATE  = PR_MCE_KILL_LATE
	};

	using enum Policy;

public: // functions

	explicit MachineCheckPolicy(const ItemType type = ItemType::PARAM_IN) :
			ValueParameter{ItemCfg{type, "policy",
				"machine check exception policy"}} {
	}

	Policy policy() const {
		return m_policy;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Policy m_policy{};
};

/// Sub-operation enum value for prctl(PR_SET_MM, op).
class MemoryMapOp :
		public ValueInParameter {
public: // types

	enum class Operation : long {
		START_CODE  = PR_SET_MM_START_CODE,
		END_CODE    = PR_SET_MM_END_CODE,
		START_DATA  = PR_SET_MM_START_DATA,
		END_DATA    = PR_SET_MM_END_DATA,
		START_STACK = PR_SET_MM_START_STACK,
		START_BRK   = PR_SET_MM_START_BRK,
		BRK         = PR_SET_MM_BRK,
		ARG_START   = PR_SET_MM_ARG_START,
		ARG_END     = PR_SET_MM_ARG_END,
		ENV_START   = PR_SET_MM_ENV_START,
		ENV_END     = PR_SET_MM_ENV_END,
		AUXV        = PR_SET_MM_AUXV,
		EXE_FILE    = PR_SET_MM_EXE_FILE,
		MAP         = PR_SET_MM_MAP,
		MAP_SIZE    = PR_SET_MM_MAP_SIZE,
	};

	using enum Operation;

public: // functions

	explicit MemoryMapOp() :
			ValueInParameter{make_item_cfg("subop", "memory map operation")} {
	}

	Operation operation() const {
		return m_op;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Operation m_op{};
};

/// Wrapper around struct prctl_mm_map.
/**
 * This structure is used to define all aspects of a process's memory map
 * instead of using a dozen of individual prctl() calls. It depends on an
 * additional system call parameter which specifies the amount of data found
 * at the pointer this points to.
 **/
class MemoryMapStruct :
		public PointerInValue {
public: // functions

	explicit MemoryMapStruct() :
			PointerInValue{make_item_cfg("map", "pointer to prctl_mm_map*")} {
		// we need access to the map_size argument which follows us.
		m_flags.set(Flag::DEFER_FILL);
	}

	/// Provides access to the raw prctl_mm_map structure.
	/**
	 * This can be nullopt when bad memory was referenced by the tracee.
	 **/
	const std::optional<struct prctl_mm_map>& map() const {
		return m_map;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	std::optional<prctl_mm_map> m_map;
};

/// Attribute to set via the PR_SET_VMA prctl().
class VirtualMemoryAttr :
		public ValueInParameter {
public: // types


	enum class Attr : long {
		/// Set the name of an anonymous memory area.
		ANON_NAME  = PR_SET_VMA_ANON_NAME
	};

	using enum Attr;

public: // functions

	explicit VirtualMemoryAttr() :
			ValueInParameter{make_item_cfg("attr", "virtual memory attribute")} {
	}

	Attr attr() const {
		return m_attr;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Attr m_attr{};
};

/// Specialized ProcessID for the SetPTracerSystemCall.
class PTracerProcessID :
		public ProcessID {
public: // functions

	explicit PTracerProcessID() :
			ProcessID{} {
	}

	std::string str() const override {
		if (pid() == cosmos::ProcessID::INVALID) {
			return "PR_SET_PTRACER_ANY";
		}

		return ProcessID::str();
	}
};

/// Enum for the PR_GET_SPECULATION_CTRL and PR_SET_SPECULATION_CTRL prctls().
class SpeculationCtrlMisfeature :
		public ValueInParameter {
public: // types

	enum class Misfeature : long {
		/// Speculative store bypass.
		STORE_BYPASS = PR_SPEC_STORE_BYPASS,
		/// Indirect branch speculation.
		INDIRECT_BRANCH = PR_SPEC_INDIRECT_BRANCH,
	};

	using enum Misfeature;

public: // functions

	explicit SpeculationCtrlMisfeature() :
			ValueInParameter{make_item_cfg("misfeature", "speculation control misfeature")} {
	}

	Misfeature misfeature() const {
		return m_misfeature;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Misfeature m_misfeature{};
};

/// Bitmask for the PR_GET_SPECULATION_CTRL and PR_SET_SPECULATION_CTRL prctls().
/**
 * It is not fully clear at first that this is actually a bitmask. Only the
 * PR_SPEC_PRCTL bit is currently used in addition to one of the setting bits.
 **/
class SpeculationCtrlSetting :
		public ValueParameter {
public: // types

	enum class Setting : long {
		/// Mitigation can be controlled via PR_SET_SPECULATION_CTRL.
		PRCTL = PR_SPEC_PRCTL,
		/// Misfeature enabled, mitigation disabled.
		ENABLE = PR_SPEC_ENABLE,
		/// Misfeature disabled, mitigation enabled.
		DISABLE = PR_SPEC_DISABLE,
		/// Like DISABLE but cannot be undone.
		FORCE_DISABLE = PR_SPEC_FORCE_DISABLE,
		/// Like DISABLE but the setting is reset upon execve().
		DISABLE_NOEXEC = PR_SPEC_DISABLE_NOEXEC,
	};

	using enum Setting;

	using Settings = cosmos::BitMask<Setting>;

public: // functions

	explicit SpeculationCtrlSetting(const ItemType type) :
			ValueParameter{ItemCfg{type, "setting", "speculation control setting"}} {
	}

	Settings settings() const {
		return m_settings;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Settings m_settings{};
};

/// Enum for the PR_SET_SYSCALL_USER_DISPATCH prctl().
class SyscallUserDispatchMode :
		public ValueInParameter {
public: // types

	enum class Mode : long {
		/// Enable the mechanism using additional parameters as configuration.
		DISPATCH_ON = PR_SYS_DISPATCH_ON,
		/// Disable the mechanism for the calling thread.
		DISPATCH_OFF = PR_SYS_DISPATCH_OFF
	};

	using enum Mode;

public: // functions

	explicit SyscallUserDispatchMode() :
			ValueInParameter{make_item_cfg("mode", "system call user dispatch mode")} {
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

/// Enum for the PR_SET_TAGGED_ADDR_CTRL prctl().
class TaggedAddressControl :
		public ValueParameter {
public: // types

	enum class Mode : long {
		/// Addresses must be untagged.
		UNTAGGED = 0,
		/// Addresses may be tagged, with exceptions.
		TAGGED_ADDR_ENABLE = PR_TAGGED_ADDR_ENABLE,
	};

	using enum Mode;

public: // functions

	explicit TaggedAddressControl(const ItemType type) :
			ValueParameter{ItemCfg{type, "mode", "tagged userspace addresses mode"}} {
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

/// Enum for the PR_GET_THP_DISABLE prctl().
class THPDisableState :
		public ReturnValue {
public: // types

	enum class Config : int {
		UNSPECIFIED = 0,
		DISABLED = 1,
		DISABLED_EXCEPT_ADVISED = 3
	};

	using enum Config;

public: // functions

	explicit THPDisableState() :
			ReturnValue{make_item_cfg("config", "THP-disable config")} {
	}

	Config config() const {
		return m_config;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Config m_config{};
};

/// Flags for the PR_SET_THP_DISABLE prctl().
class THPDisableFlags :
		public ValueInParameter {
public: // types

	enum class Flag : long {
#ifdef PR_THP_DISABLE_EXCEPT_ADVISED
		THP_DISABLE_EXCEPT_ADVICED = PR_THP_DISABLE_EXCEPT_ADVISED
#endif
	};

	using enum Flag;

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit THPDisableFlags() :
			ValueInParameter{make_item_cfg("flags", "THP-disable flags")} {
	}

	Flags flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Flags m_flags{};
};

/// Enum for the PR_GET_TIMING and PR_SET_TIMING prctl().
class TimingMode :
		public ValueParameter {
public: // types

	enum class Mode : int {
		STATISTICAL = PR_TIMING_STATISTICAL,
		TIMESTAMP = PR_TIMING_TIMESTAMP
	};

	using enum Mode;

public: // functions

	explicit TimingMode(const ItemType type) :
			ValueParameter{ItemCfg{type, "mode", "timing mode"}} {
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

/// Enum for the PR_SET_TSC prctl().
class TSCAccess :
		public ValueParameter {
public: // types

	enum class Access : int {
		ENABLE = PR_TSC_ENABLE,
		SEGV   = PR_TSC_SIGSEGV
	};

	using enum Access;

public: // functions

	explicit TSCAccess(const ItemType type) :
			ValueParameter{ItemCfg{type, "access", "timestamp counter access"}} {
	}

	Access access() const {
		return m_access;
	}

	std::string str() const override;

	static std::string to_str(const Access acc);

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Access m_access{};
};

/// Pointer-to-enum for the PR_GET_TSC prctl().
class TSCAccessPtr :
		public PointerToScalar<int> {
public: // types

	using Access = TSCAccess::Access;

	using enum Access;

public: // functions

	explicit TSCAccessPtr() :
			PointerToScalar<int>{ItemCfg{
				.label = "access", 
				.desc = "pointer to timestamp counter access"}} {
	}

	Access access() const {
		return m_access;
	}

protected: // functions

	std::string scalarToString() const override;

	void updateData(const Tracee &tracee) override;

protected: // data

	Access m_access{};
};

/// Bitmask for the PR_SET_MDWE and PR_GET_MDWE prctl().
class MemDenyWriteExecProtectionMask :
		public ValueParameter {
public: // types

	enum class Flag : int {
		REFUSE_EXEC_GAIN = PR_MDWE_REFUSE_EXEC_GAIN,
		NO_INHERIT       = PR_MDWE_NO_INHERIT
	};

	using enum Flag;

	using Mask = cosmos::BitMask<Flag>;

public: // functions

	explicit MemDenyWriteExecProtectionMask(const ItemType type) :
			ValueParameter{ItemCfg{type, "mask", "protection mask"}} {
	}

	Mask mask() const {
		return m_mask;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	Mask m_mask{};
};

/// auxv buffer for PR_GET_AUXV.
/**
 * This specializes BufferPointer to provide a cosmos::AuxVector member for
 * inspecting the actual auxv data returned by the kernel. Beware that the
 * data might be truncated due to the Tracee max buffer prefetch setting.
 **/
class AuxVectorBuffer :
		public BufferPointer {
public: // functions
	explicit AuxVectorBuffer(const SystemCallItem &size_par) :
			BufferPointer{
				size_par,
				ItemCfg{ItemType::PARAM_OUT, "auxv", "pointer to auxv buffer"},
				/*is_binary=*/true} {
	}

	const std::optional<cosmos::AuxVector>& vector() const {
		return m_auxv;
	}

	virtual void fetchRemainingData(const Tracee &) override;

protected: // functions

	void processValue(const Tracee &) override;

	void updateData(const Tracee &) override;

protected: // data

	std::optional<cosmos::AuxVector> m_auxv;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
