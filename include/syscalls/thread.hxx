#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/futex.hxx>
#include <clues/items/items.hxx>
#include <clues/items/process.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/time.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

struct CLUES_API SetTIDAddressSystemCall :
		public SystemCall {

	SetTIDAddressSystemCall() :
			SystemCall{SystemCallNr::SET_TID_ADDRESS},
			address{"addr", "thread ID location"},
			caller_tid{ItemType::RETVAL, "caller thread ID"} {
		setReturnItem(caller_tid);
		setParameters(address);
	}

	/// location where to find a futex the kernel operates on.
	/**
	 * When the calling thread exits and other threads exist in the
	 * process then this address will be manipulated with futex
	 * operations.
	 **/
	item::GenericPointerValue address;

	/// This will always be the TID of the caller.
	item::ThreadIDItem caller_tid;
};

struct CLUES_API GetRobustListSystemCall :
		public SystemCall {

	GetRobustListSystemCall() :
			SystemCall{SystemCallNr::GET_ROBUST_LIST},
			thread_id{ItemType::PARAM_IN, "thread ID"},
			list_head{"head", "pointer to robust list head"},
			size_ptr{"sizep", "pointer to robust list head size"} {
		setReturnItem(result);
		setParameters(thread_id, list_head, size_ptr);
		list_head.setBase(Base::HEX);
	}

	item::ThreadIDItem thread_id;
	/*
	 * This points to `struct robust_list_head*` defined in futex.h. It
	 * could be fully modeled, but since this is so low-level and exotic I
	 * believe there is little value in this at this point.
	 */
	item::PointerToScalar<void*> list_head;
	item::PointerToScalar<size_t> size_ptr;
	item::SuccessResult result;
};

struct CLUES_API SetRobustListSystemCall :
		public SystemCall {

	SetRobustListSystemCall() :
			SystemCall{SystemCallNr::SET_ROBUST_LIST},
			list_head{"head", "pointer to robust list head"},
			size{"size", "robust list size"} {
		setReturnItem(result);
		setParameters(list_head, size);
	}

	item::GenericPointerValue list_head;
	item::ValueInParameter size;
	item::SuccessResult result;
};

/// futex() system call with context-sensitive parameters and return values.
/**
 * This is an `ioctl()` style system call or high complexity.
 **/
struct CLUES_API FutexSystemCall :
		public SystemCall {

	FutexSystemCall() :
			SystemCall{SystemCallNr::FUTEX},
			futex_addr{"addr", "pointer to futex word"},
			result{item::SuccessResult{}} {
		/*
		 * minimal default setup, the actual parameters and return
		 * values are setup in the member functions in a
		 * context-sensitive manner.
		 */
		setReturnItem(*result);
		setParameters(futex_addr, operation);
	}

	/* fixed parameters */

	// this points to a 32-bit value which is operated on
	item::GenericPointerValue futex_addr;
	item::FutexOperation operation;

	/* context-dependent parameters */

	///! the value expected as `futex_addr` (WAIT, WAIT_REQUEUE_PI).
	std::optional<item::Uint32Value> value;
	///! number of waiters to wake up (WAKE, REQUEUE, CMP_REQUEUE, WAKE_OP, CMD_REQUEUE_PI).
	std::optional<item::Uint32Value> wake_count;
	///! signal used for asynchronous notifications (CREATE_FD).
	std::optional<item::SignalNumber> fd_sig;
	///! optional relative timeout (WAIT) or absolute timeout (WAIT_BITSET, LOCK_PI, LOCK_PI2).
	std::optional<item::TimespecParameter> timeout;
	///! "uaddr2" requeue address (REQUEUE, CMP_REQUEUE, CMP_REQUEUE_PI, WAIT_REQUEUE_PI) or additional futex (WAKE_OP).
	std::optional<item::GenericPointerValue> futex2_addr;
	///! "val3" used for comparison in CMP_REQUEUE, CMP_REQUEUE_PI.
	std::optional<item::Uint32Value> requeue_value;
	///! "val2", upper limit on waiters to be requeued to addr2 (REQUEUE, CMP_REQUEUE, CMP_REQUEUE_PI).
	std::optional<item::Uint32Value> requeue_limit;
	///! "val2", number of waiters at `futex2_addr` to wakeup (WAKE_OP).
	std::optional<item::Uint32Value> wake_count2;
	///! instructions for how to perform the wake operation (WAKE_OP).
	std::optional<item::FutexWakeOperation> wake_op;
	///! bitset to restrict wait/wakeup (FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET).
	std::optional<item::GenericPointerValue> bitset;

	/* context-dependent return values */

	///! number of waiters woken up (WAKE, WAKE_OP).
	std::optional<item::ReturnValue> num_woken_up;
	///! new file descriptor (CREATE_FD).
	std::optional<item::FileDescriptor> new_fd;
	///! success status (all remaining operations).
	std::optional<item::SuccessResult> result;

protected: // functions

	bool check2ndPass() override;

	void prepareNewSystemCall() override;
};

} // end ns
