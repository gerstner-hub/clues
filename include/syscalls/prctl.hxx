#pragma once

// C++
#include <optional>

// clues
#include <clues/arch.hxx>
#include <clues/items/caps.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/items.hxx>
#include <clues/items/prctl.hxx>
#include <clues/items/seccomp.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

#ifdef CLUES_HAVE_ARCH_PRCTL

/// x86-specific prctl() extension.
struct ArchPrctlSystemCall :
		public SystemCall {

	ArchPrctlSystemCall() :
			SystemCall{SystemCallNr::ARCH_PRCTL} {
		setParameters(op);
		result.emplace();
		setReturnItem(*result);
	}

	/* parameters */
	item::ArchOpParameter op;
	/// On/off value for SET_CPUID.
	std::optional<item::ULongValue> on_off;
	/// new FS/GS base for SET_FS/SET_GS
	std::optional<item::GenericPointerValue> set_addr;
	/// pointer to base for GET_FS/GET_GS
	std::optional<item::PointerToScalar<unsigned long>> get_addr;
	/* return values */
	std::optional<item::SuccessResult> result;
	/// On/off return for GET_CPUID.
	std::optional<item::IntValue> on_off_ret;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

#endif // HAVE_ARCH_PRCTL

/// Base type for prctl() system calls.
/**
 * prctl() is a varargs system call similar to ioctl(). Due to the many
 * different types of parameters and return values, specializations of this
 * type exist for the more complex operations.
 *
 * The only fixed parameter is the first integer argument `op` which specifies
 * the operation to be carried out and on which the interpretation of the rest
 * of the parameters and the return value depend.
 *
 * Some commonly used parameter and return types are shared by derived types
 * so check the class documentation for what to expect.
 *
 * The following operations are covered by the base class type:
 *
 * - GET_DUMPABLE, SET_DUMPABLE
 * - GET_IO_FLUSHER
 * - GET_KEEPCAPS, SET_KEEPCAPS
 * - GET_NO_NEW_PRIVS, SET_NO_NEW_PRIVS
 * - SET_CHILD_SUBREAPER
 * - GET_SECCOMP
 * - TASK_PERF_EVENTS_ENABLE, TASK_PERF_EVENTS_DISABLE
 *
 * The following operations are covered by derived types:
 *
 * - SET_MM: prctl::MemoryMapSystemCall
 * - MCE_KILL: prctl::MachineCheckKillSystemCall
 * - MCE_KILL_GET: prctl::MachineCheckKillGetSystemCall
 * - CAP_AMBIENT: prctl::CapAmbientSystemCall
 * - CAPBSET_READ, CAPBSET_DROP: prctl::CapBSetSystemCall
 * - GET_CHILD_SUBREAPER: prctl::GetChildSubReaperSystemCall
 * - PR_GET_NAME/PR_SET_NAME: prctl::NameSystemCall
 * - PR_SET_VMA: prctl::VirtualMemoryAttrSystemCall
 * - PR_SET_PDEATHSIG, PR_GET_PDEATHSIG: prctl::ParentDeathSignalSystemCall
 * - PR_SET_PTRACER: prctl::SetPTracerSystemCall
 * - PR_SET_SECCOMP: prctl::SetSecCompSystemCall
 * - PR_GET_SECUREBITS: prctl::GetSecureBitsSystemCall
 * - PR_SET_SECUREBITS: prctl::SetSecureBitsSystemCall
 * - PR_GET_SPECULATION_CTRL: prctl::GetSpeculationControlSystemCall
 * - PR_SET_SPECULATION_CTRL: prctl::SetSpeculationControlSystemCall
 * - PR_SET_SYSCALL_USER_DISPATCH: prctl::SetSyscallUserDispatchSystemCall
 * - PR_GET_TAGGED_ADDR_CTRL: prctl::GetTaggedAddrControlSystemCall
 * - PR_SET_TAGGED_ADDR_CTRL: prctl::SetTaggedAddrControlSystemCall
 * - PR_GET_THP_DISABLE: prctl::GetTHPDisableSystemCall
 * - PR_SET_THP_DISABLE: prctl::SetTHPDisableSystemCall
 * - PR_GET_TID_ADDRESS: prctl::GetTIDAddressSystemCall
 * - PR_SET_TIMERSLACK: prctl::SetTimerSlackSystemCall
 * - PR_GET_TIMING: prctl::GetTimingModeSystemCall
 * - PR_SET_TIMING: prctl::SetTimingModeSystemCall
 * - PR_GET_TSC: prctl::GetTSCAccessSystemCall
 * - PR_SET_TSC: prctl::SetTSCAccessSystemCall
 * - PR_GET_MDWE: prctl::GetMemDenyWriteExecSystemCall
 * - PR_SET_MDWE: prctl::SetMemDenyWriteExecSystemCall
 * - PR_GET_AUXV: prctl::GetAuxVectorSystemCall
 *
 * The following operations use the `bool_setting`:
 *
 * - SET_DUMPABLE
 * - SET_IO_FLUSHER
 * - SET_CHILD_SUBREAPER
 * - SET_KEEPCAPS
 * - SET_NO_NEW_PRIVS
 *
 * The following operations use the `bool_res` return value:
 *
 * - GET_DUMPABLE
 * - GET_IO_FLUSHER
 * - GET_KEEPCAPS
 * - GET_NO_NEW_PRIVS
 *
 * The following operations use the `int_res` return value:
 *
 * - GET_SECCOMP
 * - GET_TIMERSLACK
 *
 * The `res` success status is used by various derived types and the base
 * class implementation alike.
 **/
struct PrCtlSystemCall :
		public SystemCall {

	explicit PrCtlSystemCall() :
			SystemCall{SystemCallNr::PRCTL} {
		setParameters(op);
	}

	/// Factory function to create a concrete PrCtlSystemCall() instance.
	static SystemCallPtr createSystemCall(const SystemCallInfo &info);

	/* fixed parameters */

	/// The only fixed parameter: the type of process operation.
	item::ProcessOp op;

	/* vararg parameters */

	/// New boolean value for attribute.
	/**
	 * This is available for the following Operation contexts:
	 *
	 * - GET_IO_FLUSHER
	 * - SET_CHILD_SUBREAPER
	 * - SET_DUMPABLE
	 * - SET_KEEPCAPS
	 **/
	std::optional<item::BoolValue> bool_setting;

	/* return values */

	/// Regular success status result.
	/**
	 * This is used (on success) for the following Operation values:
	 *
	 * - CAP_AMBIENT (except for sub-operation CAP_AMBIENT_IS_SET)
	 * - CAPBSET_DROP
	 * - MM_SET
	 * - GET_CHILD_SUBREAPER
	 * - SET_CHILD_SUBREAPER
	 **/
	std::optional<item::SuccessResult> res;

	/// Boolean indicator.
	/**
	 * This is available for the following Operation values:
	 *
	 * - CAP_AMBIENT (only for sub-operation CAP_AMBIENT_IS_SET)
	 * - CAPBSET_READ
	 * - GET_DUMPABLE
	 * - GET_IO_FLUSHER
	 * - SET_IO_FLUSHER
	 * - SET_CHILD_SUBREAPER
	 **/
	std::optional<item::BoolValue> bool_res;

	/// Integer return value.
	/**
	 * This is available for the following Operation values:
	 *
	 * - GET_SECCOMP (0 if not in secure computing mode, 2 if in secure
	 *   computing mode but this prctl() call is allowed). This is
	 *   available for the following Operation values:
	 *
	 *   - GET_SECCOMP (0 if not in secure computing mode, 2 if in secure
	 *   computing mode but this prctl() call is allowed).
	 **/
	std::optional<item::IntValue> int_res;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;

	void clearOptArgs();
	void clearOptRetVals();

	void setBoolReturn();
	void setSuccessReturn();
};

/// Base type for specialized prctl() system call types that have no dynamic parameters.
class FixedPrCtlSystemCall :
		public PrCtlSystemCall {

protected: // functions

	bool check2ndPass(const Tracee &) override {
		return false;
	}

	void prepareNewSystemCall() override {
		/* nothing to reset */
	}
};

/// Catch-all type for unknown prctl operations.
class UnknownPrCtlSystemCall :
		public FixedPrCtlSystemCall {
public: // functions
	explicit UnknownPrCtlSystemCall() {
		setSuccessReturn();
		addParameters(unknown);
	}

public: // data

	item::UnknownItem unknown;
};

/* nested namespace for all PrCtlSystemCall specializations */
namespace prctl {

/// Specialization of PrCtlSystemCall for the SET_MM operation.
/**
 * All of the SET_MM sub-operations use the `res` success status result.
 **/
class MemoryMapSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit MemoryMapSystemCall() :
			PrCtlSystemCall{} {
		addParameters(mm_op);
		// all SET_MM operation use the regular success result.
		res.emplace();
		setReturnItem(*res);
	}

public: // data

	/// sub-operation for Operation::SET_MM.
	item::MemoryMapOp mm_op;
	/// memory map setting for most of the MemoryMapOp sub-operations.
	std::optional<item::GenericPointerValue> addr;
	/// out pointer for MemoryMapOp::MAP_SIZE.
	std::optional<item::PointerToScalar<unsigned int>> reported_size;
	/// file descriptor for MemoryMapOp::EXE_FILE.
	std::optional<item::FileDescriptor> exe_fd;
	/// pointer to prctl_mm_map* for MemoryMapOp::MAP.
	std::optional<item::MemoryMapStruct> mm_struct;
	/// size of area pointed to by `map_struct`.
	std::optional<item::ULongValue> mm_struct_size;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for the MCE_KILL operation.
/**
 * This prctl operation always uses the `res` success status return value.
 **/
class MachineCheckKillSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit MachineCheckKillSystemCall() :
			PrCtlSystemCall{} {
		addParameters(mce_kill_op);
		res.emplace();
		setReturnItem(*res);
	}

public: // data

	/// sub-operation to carry out.
	item::MachineCheckOp mce_kill_op;
	/// Policy for sub-op MachineCheckOp::SET.
	std::optional<item::MachineCheckPolicy> policy;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for the MCE_KILL_GET operation.
/**
 * This prctl operation has no additional parameters and always returns
 * `policy_res`.
 **/
class MachineCheckKillGetSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit MachineCheckKillGetSystemCall() :
			PrCtlSystemCall{},
			policy_res{ItemType::RETVAL} {
		setReturnItem(policy_res);
	}

public: // data

	/// Policy return for Operation::MCE_KILL_GET.
	item::MachineCheckPolicy policy_res;

protected: // functions

	bool check2ndPass(const Tracee&) override {
		/* no more vararg parameters */
		return false;
	}

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for the CAP_AMBIENT operation.
/**
 * This prctl operation uses `bool_res` for AmbientCapOp::CAP_AMBIENT_IS_SET,
 * otherwise the `res` success status.
 **/
class CapAmbientSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit CapAmbientSystemCall() :
			PrCtlSystemCall{} {
		addParameters(ambient_op);
	}
public: // data

	/// sub-operation for Operation::CAP_AMBIENT.
	item::AmbientCapOp ambient_op;
	// available for `ambient_op` other than CLEAR_ALL.
	std::optional<item::Capability> cap;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for the CAPBSET_{READ,DROP} operations.
/**
 * This prctl operation uses `bool_res` for CAPBSET_READ, otherwise the `res`
 * success status.
 **/
class CapBSetSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit CapBSetSystemCall() :
			PrCtlSystemCall{} {
		addParameters(cap);
	}

public: // data

	item::Capability cap;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for the GET_CHILD_SUBREAPER operation.
/**
 * For return value the `res` success status is used by this system call.
 **/
class GetChildSubReaperSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetChildSubReaperSystemCall() :
			is_subreaper{make_item_cfg("subreaper", "is child-subreaper")} {
		addParameters(is_subreaper);
		setSuccessReturn();
	}

public: // data

	/// Current child-subreaper setting filled in by the kernel.
	item::PointerToScalar<int> is_subreaper;
};

/// Specialization of PrCtlSystemCall for the PR_SET_VMA operation.
/**
 * This uses the `res` success status as return value.
 **/
class VirtualMemoryAttrSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit VirtualMemoryAttrSystemCall() :
			attr{},
			addr{make_item_cfg("addr", "memory area start address")},
			size{make_item_cfg("size", "extent of memory area")},
			name{item::StringData{make_item_cfg("name", "anonymous memory area name")}} {
		addParameters(attr, addr, size, *name);
		setSuccessReturn();
	}

public: // data

	/// The attribute to operate on.
	item::VirtualMemoryAttr attr;
	item::GenericPointerValue addr;
	item::ULongValue size;
	/* currently the only possible parameter, but we keep it optional to
	 * be compatible with future extensions of the API */
	/// The name for VirtualMemoryAttr::ANON_NAME.
	std::optional<item::StringData> name;
};

/// Specialization of PrCtlSystemCall for PR_GET_NAME and PR_SET_NAME.
/**
 * This type is used for both, getting the thread name and setting the thread
 * name. The `name` member for getting the thread name is only updated during
 * system exit, accordingly.
 *
 * This uses the `res` success status as return value.
 **/
class NameSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit NameSystemCall() :
			PrCtlSystemCall{} {
		setSuccessReturn();
	}

public: // data

	/// The in or out string parameter.
	std::optional<item::StringData> name;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for PR_GET_PDEATHSIG and PR_SET_PDEATHSIG
/**
 * This system call uses the `res` exit status return value.
 **/
class ParentDeathSignalSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit ParentDeathSignalSystemCall() :
			PrCtlSystemCall{} {
		setSuccessReturn();
	}

public: // data

	/// The new signal to set for PR_SET_PDEATHSIG.
	std::optional<item::SignalNumber> new_signal;
	/// The currently set signal for PR_GET_PDEATHSIG.
	std::optional<item::PointerToScalar<cosmos::SignalNr>> cur_signal;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;
};

/// Specialization of PrCtlSystemCall for PR_SET_PTRACER.
/**
 * This system call uses the `res` exit status return value.
 **/
class SetPTracerSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetPTracerSystemCall() {
		setSuccessReturn();
		addParameters(pid);
	}

public: // data

	/// The new signal to set for PR_SET_PDEATHSIG.
	item::PTracerProcessID pid;
};

/// Specialization of PrCtlSystemCall for PR_SET_SECCOMP.
/**
 * This system call uses the `res` exit status return value.
 **/
class SetSecCompSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit SetSecCompSystemCall() :
			PrCtlSystemCall{} {
		setSuccessReturn();
		addParameters(mode);
	}

public: // data

	/// The new secure computing mode to set.
	item::SecCompMode mode;
	/// For SecCompMode::FILTER this contains the filter program to be set.
	std::optional<item::FilterProg> filter;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override {
		filter.reset();
		dropParameters(2);
	}
};

/// Specialization of PrCtlSystemCall for PR_GET_SECUREBITS.
/**
 * This call takes no additional parameters and always returns `bits`, the
 * secure bits bitmask.
 **/
class GetSecureBitsSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetSecureBitsSystemCall() :
       			bits{ItemType::RETVAL} {
		setReturnItem(bits);
	}

public: // data

	item::SecureBits bits;
};

/// Specialization of PrCtlSystemCall for PR_SET_SECUREBITS.
/**
 * This call takes a SecureBits parameter and always returns a `res` success
 * status.
 **/
class SetSecureBitsSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetSecureBitsSystemCall() :
			bits{ItemType::PARAM_IN} {
		addParameters(bits);
		setSuccessReturn();
	}

public: // data

	item::SecureBits bits;
};

/// Specialization of PrCtlSystemCall for PR_GET_SPECULATION_CTRL.
/**
 * This type uses `setting` as return value and none of the base class
 * optional parameters.
 **/
class GetSpeculationControlSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetSpeculationControlSystemCall() :
			setting{ItemType::RETVAL} {
		addParameters(misfeature);
		setReturnItem(setting);
	}

public: // data

	item::SpeculationCtrlMisfeature misfeature;
	item::SpeculationCtrlSetting setting;
};

/// Specialization of PrCtlSystemCall for PR_SET_SPECULATION_CTRL.
/**
 * This type uses the `res` success status return value from the base class.
 **/
class SetSpeculationControlSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetSpeculationControlSystemCall() :
			setting{ItemType::PARAM_IN} {
		addParameters(misfeature, setting);
		setSuccessReturn();
	}

public: // data

	item::SpeculationCtrlMisfeature misfeature;
	item::SpeculationCtrlSetting setting;
};

/// Specialization of PrCtlSystemCall for PR_SET_SYSCALL_USER_DISPATCH.
/**
 * This type uses the `res` success status return value from the base class.
 *
 * The additional optional parameters are only used for
 * SyscallUserDispatchMode::DISPATCH_ON.
 **/
class SetSyscallUserDispatchSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit SetSyscallUserDispatchSystemCall() :
			PrCtlSystemCall{} {
		setSuccessReturn();
		addParameters(mode);
	}

public: // data

	item::SyscallUserDispatchMode mode;
	/// Memory location of code which will be excluded from the mechanism.
	std::optional<item::GenericPointerValue> offset;
	/// Size of the code area found at `offset`.
	std::optional<item::ULongValue> size;
	/// Userspace switch which decides whether the mechanism is in effect or not.
	std::optional<item::GenericPointerValue> on_off_switch;

protected: // functions

	bool check2ndPass(const Tracee &) override;

	void prepareNewSystemCall() override {
		offset.reset();
		size.reset();
		on_off_switch.reset();
		dropParameters(2);
	}
};

/// Specialization of PrCtlSystemCall for PR_GET_TAGGED_ADDR_CTRL.
/**
 * This type uses the dedicated `mode` return value in the derived type. There
 * are no additional parameters.
 **/
class GetTaggedAddrControlSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetTaggedAddrControlSystemCall() :
			mode{ItemType::RETVAL} {
		setReturnItem(mode);
	}

public: // data

	item::TaggedAddressControl mode;
};

/// Specialization of PrCtlSystemCall for PR_SET_TAGGED_ADDR_CTRL.
/**
 * This type uses the `res` success status return from the base class.
 **/
class SetTaggedAddrControlSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetTaggedAddrControlSystemCall() :
			mode{ItemType::PARAM_IN} {
		setSuccessReturn();
		addParameters(mode);
	}

public: // data

	item::TaggedAddressControl mode;
};

/// Specialization of PrCtlSystemCall for PR_GET_THP_DISABLE.
class GetTHPDisableSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetTHPDisableSystemCall() {
		setReturnItem(config);
	}

public: // data

	item::THPDisableState config;
};

/// Specialization of PrCtlSystemCall for PR_SET_THP_DISABLE.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 *
 * The `flags` optional parameter is only available if `thp_disable.value() ==
 * true`.
 **/
class SetTHPDisableSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit SetTHPDisableSystemCall() :
			thp_disable{ItemCfg{.label = "thp_disable"}} {
		setSuccessReturn();
		addParameters(thp_disable);
	}

public: // data

	item::BoolValue thp_disable;
	std::optional<item::THPDisableFlags> flags;

protected: // functions

	bool check2ndPass(const Tracee &) override {
		if (thp_disable.value() == true) {
			flags.emplace();
			addParameters(*flags);
			return true;
		}

		return false;
	}

	void prepareNewSystemCall() override {
		dropParameters(2);
		flags.reset();
	}
};

/// Specialization of PrCtlSystemCall for PR_GET_TID_ADDRESS.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 **/
class GetTIDAddressSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetTIDAddressSystemCall() :
			addr{make_item_cfg("addrp", "pointer to int*")} {
		setSuccessReturn();
		addParameters(addr);
	}

public: // data

	item::PointerToScalar<ForeignPtr> addr;
};

/// Specialization of PrCtlSystemCall for PR_SET_TIMERSLACK.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 **/
class SetTimerSlackSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetTimerSlackSystemCall() :
			slack{ItemCfg{ItemType::PARAM_IN, "slack", "new current timer slack"}} {
		setSuccessReturn();
		addParameters(slack);
	}

public: // data

	/// The new timer slack to set or 0 to use the default.
	item::ULongValue slack;
};

/// Specialization of PrCtlSystemCall for PR_SET_TIMING.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 **/
class SetTimingModeSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetTimingModeSystemCall() :
			mode{ItemType::PARAM_IN} {
		setSuccessReturn();
		addParameters(mode);
	}

public: // data

	/// The new timing mode to set.
	item::TimingMode mode;
};

/// Specialization of PrCtlSystemCall for PR_GET_TIMING.
/**
 * This class uses the specialized TimingMode return value and otherwise has
 * no additional parameters.
 **/
class GetTimingModeSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetTimingModeSystemCall() :
			mode{ItemType::RETVAL} {
		setReturnItem(mode);
	}

public: // data

	/// The current timing mode which is active.
	item::TimingMode mode;
};

/// Specialization of PrCtlSystemCall for PR_SET_TSC.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 **/
class SetTSCAccessSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetTSCAccessSystemCall() :
			access{ItemType::PARAM_IN} {
		setSuccessReturn();
		addParameters(access);
	}

public: // data

	/// The new TSC access mode.
	item::TSCAccess access;
};

/// Specialization of PrCtlSystemCall for PR_GET_TSC.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 *
 * The additional parameter is apointer to the a variable where to store the
 * current TSC access mode.
 **/
class GetTSCAccessSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetTSCAccessSystemCall() :
			access{} {
		setSuccessReturn();
		addParameters(access);
	}

public: // data

	/// Out pointer to The current TSC access mode.
	item::TSCAccessPtr access;
};

/// Specialization of PrCtlSystemCall for PR_GET_MDWE.
/**
 * This uses a specialized MemDenyWriteExecProtectionMask return value and no
 * additional parameters.
 **/
class GetMemDenyWriteExecSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetMemDenyWriteExecSystemCall() :
			mask{ItemType::RETVAL} {
		setReturnItem(mask);
	}

public: // data

	item::MemDenyWriteExecProtectionMask mask;
};

/// Specialization of PrCtlSystemCall for PR_SET_MDWE.
/**
 * The return type for this variant of prctl() is always the `res` success
 * status from the base class.
 *
 * One additional parameter specifies the new bitmask for mem-deny-exec
 * protection.
 **/
class SetMemDenyWriteExecSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit SetMemDenyWriteExecSystemCall() :
			mask{ItemType::PARAM_IN} {
		setSuccessReturn();
		addParameters(mask);
	}

public: // data

	item::MemDenyWriteExecProtectionMask mask;
};

/// Specialization of PrCtlSystemCall for PR_GET_AUXV.
/**
 * The `aux_vector` member provides full access to the auxiliary vector data
 * via the cosmos::AuxVector API.
 *
 * The `filled_size` return value contains the number of bytes actually filled
 * in.
 **/
class GetAuxVectorSystemCall :
		public FixedPrCtlSystemCall {
public: // functions

	explicit GetAuxVectorSystemCall() :
			buffer_size{make_item_cfg("size", "size of aux vector buffer")},
			aux_vector{buffer_size},
			filled_size{ItemCfg{ItemType::RETVAL, "bytes", "filled bytes"}} {
		setReturnItem(filled_size);
		addParameters(aux_vector, buffer_size);
	}

public: // data

	item::ULongValue buffer_size;
	item::AuxVectorBuffer aux_vector;
	item::SizeValue filled_size;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns prctl

} // end ns
