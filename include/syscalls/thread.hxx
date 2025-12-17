#pragma once

// clues
#include <clues/items/futex.hxx>
#include <clues/items/items.hxx>
#include <clues/items/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

struct SetTidAddressSystemCall :
		public SystemCall {

	SetTidAddressSystemCall() :
			SystemCall{SystemCallNr::SET_TID_ADDRESS},
			address{"addr", "thread ID location"},
			caller_tid{"tid", "caller thread ID"} {
		setReturnItem(caller_tid);
		setParameters(address);
	}

	item::GenericPointerValue address;
	item::ValueOutParameter caller_tid;
};

struct GetRobustListSystemCall :
		public SystemCall {

	GetRobustListSystemCall() :
			SystemCall{SystemCallNr::GET_ROBUST_LIST},
			thread_id{"tid", "thread ID"},
			list_head{"head", "pointer to robust list head"},
			size_ptr{"sizep", "pointer to robust list size"} {
		setReturnItem(result);
		setParameters(thread_id, list_head, size_ptr);
	}

	item::ValueInParameter thread_id;
	item::GenericPointerValue list_head;
	// TODO: new parameter type which also prints the size stored on in-/output
	item::GenericPointerValue size_ptr;
	item::SuccessResult result;
};

struct SetRobustListSystemCall :
		public SystemCall {

	SetRobustListSystemCall() :
			SystemCall{SystemCallNr::SET_ROBUST_LIST},
			list_head{"head", "point to robust list head"},
			size{"size", "robust list size"} {
		setReturnItem(result);
		setParameters(list_head, size);
	}

	item::GenericPointerValue list_head;
	item::ValueInParameter size;
	item::SuccessResult result;
};

/*
 * TODO: this requires context-sensitive interpretation of the non-error
 * returns (the `operation` is the context).
 * TODO: allows some special operations that might need to be considered as
 * well
 */
struct FutexSystemCall :
		public SystemCall {

	FutexSystemCall() :
			SystemCall{SystemCallNr::FUTEX},
			futex_addr{"addr", "pointer to futex word"},
			value{"val"},
			timeout{"timeout"},
			requeue_futex{"uaddr2", "requeue futex"},
			requeue_check_val{"val3", "requeue check value"},
			num_woken_up{"nwokenup", "processes woken up"} {
		setReturnItem(num_woken_up);
		setParameters(futex_addr, operation, value, timeout, requeue_futex, requeue_check_val);
	}

	item::GenericPointerValue futex_addr;
	item::FutexOperation operation;
	item::ValueInParameter value;
	item::TimespecParameter timeout;
	item::GenericPointerValue requeue_futex;
	item::ValueInParameter requeue_check_val;
	item::ValueOutParameter num_woken_up;
};

} // end ns
