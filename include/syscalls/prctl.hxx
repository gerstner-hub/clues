#pragma once

// C++
#include <optional>

// clues
#include <clues/arch.hxx>
#include <clues/items/caps.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/items.hxx>
#include <clues/items/prctl.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

#ifdef CLUES_HAVE_ARCH_PRCTL

/// x86-specific prctl() extension.
struct CLUES_API ArchPrctlSystemCall :
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
 * The following operations are covered by derived types:
 *
 * - SET_MM: prctl::MemoryMapSystemCall
 * - MCE_KILL: prctl::MachineCheckKillSystemCall
 * - MCE_KILL_GET: prctl::MachineCheckKillGetSystemCall
 * - CAP_AMBIENT: prctl::CapAmbientSystemCall
 * - CAPBSET_READ, CAPBSET_DROP: prctl::CapBSetSystemCall
 * - GET_CHILD_SUBREAPER: prctl::GetChildSubReaperSystemCall
 *
 * The following operations use the `bool_setting`:
 *
 * - SET_DUMPABLE
 * - SET_IO_FLUSHER
 * - SET_CHILD_SUBREAPER
 * - SET_KEEPCAPS
 *
 * The following operations use the `bool_res` return value:
 *
 * - GET_DUMPABLE
 * - GET_IO_FLUSHER
 * - GET_KEEPCAPS
 **/
struct CLUES_API PrCtlSystemCall :
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

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;

	void clearOptArgs();
	void clearOptRetVals();

	void setBoolReturn();
	void setSuccessReturn();
};

/* nested namespace for all PrCtlSystemCall specializations */
namespace prctl {

/// Specialization of PrCtlSystemCall for the SET_MM operation.
/**
 * All of the SET_MM sub-operations use the `res` success status result.
 **/
class CLUES_API MemoryMapSystemCall :
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
class CLUES_API MachineCheckKillSystemCall :
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
class CLUES_API MachineCheckKillGetSystemCall :
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
class CLUES_API CapAmbientSystemCall :
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
class CLUES_API CapBSetSystemCall :
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
class CLUES_API GetChildSubReaperSystemCall :
		public PrCtlSystemCall {
public: // functions

	explicit GetChildSubReaperSystemCall() :
			PrCtlSystemCall{},
			is_subreaper{"subreaper", "is child-subreaper"} {
		addParameters(is_subreaper);
		setSuccessReturn();
	}

public: // data

	/// Current child-subreaper setting filled in by the kernel.
	item::PointerToScalar<long> is_subreaper;

protected: // functions

	bool check2ndPass(const Tracee&) override {
		return false;
	}

	void prepareNewSystemCall() override {
		/* nothing to reset */
	}
};

} // end ns prctl

} // end ns
