// clues
#include <clues/syscalls/thread.hxx>

namespace clues {

void FutexSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	m_pars.erase(m_pars.begin() + 2, m_pars.end());

	/* args */
	value.reset();
	wake_count.reset();
	fd_sig.reset();
	timeout.reset();
	futex2_addr.reset();
	requeue_value.reset();
	requeue_limit.reset();
	wake_count2.reset();
	wake_op.reset();
	bitset.reset();

	/* retvals */
	num_woken_up.reset();
	new_fd.reset();

	// setup the default return value
	result.emplace(item::SuccessResult{});
	setReturnItem(*result);
}

bool FutexSystemCall::check2ndPass() {
	using enum item::FutexOperation::Command;

	auto setNewReturnItem = [this](auto &new_ret) {
		result.reset();
		setReturnItem(new_ret);
	};

	auto setWokenUpReturnValue = [this, setNewReturnItem]() {
		num_woken_up.emplace(item::ReturnValue{"nwokenup", "number of waiters woken up"});
		setNewReturnItem(*num_woken_up);
	};

	const auto command = operation.command();

	switch (command) {
	case WAIT: [[fallthrough]];
	case WAIT_BITSET:
		value.emplace(item::Uint32Value{"value"});
		timeout.emplace(item::TimespecParameter{"timeout"});
		if (command == WAIT) {
			setParameters(*value, *timeout);
		} else {
			bitset.emplace(item::GenericPointerValue{"bitset"});
			setParameters(*value, *timeout, item::unused, *bitset);
		}
		break;
	case WAKE: [[fallthrough]];
	case WAKE_BITSET:
		wake_count.emplace(item::Uint32Value{"nwakeup", "number of waiters to wake up"});
		if (command == WAKE) {
			setParameters(*wake_count);
		} else {
			bitset.emplace(item::GenericPointerValue{"bitset"});
			setParameters(*wake_count, item::unused, item::unused, *bitset);
		}

		setWokenUpReturnValue();
		break;
	case CREATE_FD:
		/*
		 * this operation is not supported anymore, but we model it
		 * anyway
		 */
		fd_sig.emplace(item::SignalNumber{});
		new_fd.emplace(item::FileDescriptor{});
		setParameters(*fd_sig);
		new_fd.emplace(item::FileDescriptor{ItemType::RETVAL});
		setNewReturnItem(*new_fd);
		break;
	case REQUEUE: [[fallthrough]];
	case CMP_REQUEUE: [[fallthrough]];
	case CMP_REQUEUE_PI:
		wake_count.emplace(item::Uint32Value{"nwakeup", "number of waiters to wake up"});
		requeue_limit.emplace(item::Uint32Value{"val2", "max number of waiters to requeue"});
		futex2_addr.emplace(item::GenericPointerValue{"addr2", "requeue address"});
		if (command == REQUEUE) {
			setParameters(*wake_count, *requeue_limit, *futex2_addr);
		} else {
			requeue_value.emplace(item::Uint32Value{"val3", "comparison value"});
			setParameters(*wake_count, *requeue_limit, *futex2_addr, *requeue_value);
		}

		setWokenUpReturnValue();
		break;
	case WAKE_OP:
		wake_count.emplace(item::Uint32Value{"nwakeup", "number of waiters to wake up at addr1"});
		wake_count2.emplace(item::Uint32Value{"nwakeup2", "number of waiters to wake up at addr2"});
		futex2_addr.emplace(item::GenericPointerValue{"addr2", "op-futex"});
		wake_op.emplace(item::FutexWakeOperation{});
		setParameters(*wake_count, *wake_count2, *futex2_addr, *wake_op);

		setWokenUpReturnValue();
		break;
	case LOCK_PI: [[fallthrough]];
	case LOCK_PI2:
		// absolute timeout measured against CLOCK_REALTIME (or
		// MONOTONIC in case of LOCK_PI2, if the CLOCK_REALTIME flag
		// is not passed in `operation`.
		timeout.emplace(item::TimespecParameter{"timeout"});
		setParameters(item::unused, *timeout);
		break;
	case TRYLOCK_PI: [[fallthrough]];
	case UNLOCK_PI:
		// none of the extra arguments are used in these cases
		break;
	case WAIT_REQUEUE_PI:
		value.emplace(item::Uint32Value{"value"});
		// absolute timeout
		timeout.emplace(item::TimespecParameter{"timeout"});
		futex2_addr.emplace(item::GenericPointerValue{"addr2", "requeue address"});
		setParameters(*value, *timeout, *futex2_addr);
		break;
	default:
		/* unknown operation? keep defaults. */
		break;
	}

	return true;
}

} // end ns
