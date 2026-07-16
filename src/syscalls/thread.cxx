// clues
#include <clues/syscalls/thread.hxx>

namespace clues {

void FutexSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	dropParameters(2);

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
	result.emplace();
	setReturnItem(*result);
}

bool FutexSystemCall::check2ndPass(const Tracee &) {
	using enum item::FutexOperation::Command;

	auto setNewReturnItem = [this](auto &new_ret) {
		result.reset();
		setReturnItem(new_ret);
	};

	auto setWokenUpReturnValue = [this, setNewReturnItem]() {
		num_woken_up.emplace(make_item_cfg("nwokenup", "number of waiters woken up"));
		setNewReturnItem(*num_woken_up);
	};

	const auto command = operation.command();

	switch (command) {
	case WAIT: [[fallthrough]];
	case WAIT_BITSET:
		value.emplace(ItemCfg{.label = "value"});
		timeout.emplace(ItemCfg{.label = "timeout"});
		if (command == WAIT) {
			addParameters(*value, *timeout);
		} else {
			bitset.emplace(ItemCfg{.label = "bitset"});
			addParameters(*value, *timeout, item::unused, *bitset);
		}
		break;
	case WAKE: [[fallthrough]];
	case WAKE_BITSET:
		wake_count.emplace(make_item_cfg("nwakeup", "number of waiters to wake up"));
		if (command == WAKE) {
			addParameters(*wake_count);
		} else {
			bitset.emplace(ItemCfg{.label = "bitset"});
			addParameters(*wake_count, item::unused, item::unused, *bitset);
		}

		setWokenUpReturnValue();
		break;
	case CREATE_FD:
		/*
		 * this operation is not supported anymore, but we model it
		 * anyway
		 */
		fd_sig.emplace();
		new_fd.emplace();
		addParameters(*fd_sig);
		new_fd.emplace(ItemCfg{.type = ItemType::RETVAL});
		setNewReturnItem(*new_fd);
		break;
	case REQUEUE: [[fallthrough]];
	case CMP_REQUEUE: [[fallthrough]];
	case CMP_REQUEUE_PI:
		wake_count.emplace(make_item_cfg("nwakeup", "number of waiters to wake up"));
		requeue_limit.emplace(make_item_cfg("val2", "max number of waiters to requeue"));
		futex2_addr.emplace(make_item_cfg("addr2", "requeue address"));
		if (command == REQUEUE) {
			addParameters(*wake_count, *requeue_limit, *futex2_addr);
		} else {
			requeue_value.emplace(make_item_cfg("val3", "comparison value"));
			addParameters(*wake_count, *requeue_limit, *futex2_addr, *requeue_value);
		}

		setWokenUpReturnValue();
		break;
	case WAKE_OP:
		wake_count.emplace(make_item_cfg("nwakeup", "number of waiters to wake up at addr1"));
		wake_count2.emplace(make_item_cfg("nwakeup2", "number of waiters to wake up at addr2"));
		futex2_addr.emplace(make_item_cfg("addr2", "op-futex"));
		wake_op.emplace();
		addParameters(*wake_count, *wake_count2, *futex2_addr, *wake_op);

		setWokenUpReturnValue();
		break;
	case LOCK_PI: [[fallthrough]];
	case LOCK_PI2:
		// absolute timeout measured against CLOCK_REALTIME (or
		// MONOTONIC in case of LOCK_PI2, if the CLOCK_REALTIME flag
		// is not passed in `operation`.
		timeout.emplace(ItemCfg{.label = "timeout"});
		addParameters(item::unused, *timeout);
		break;
	case TRYLOCK_PI: [[fallthrough]];
	case UNLOCK_PI:
		// none of the extra arguments are used in these cases
		break;
	case WAIT_REQUEUE_PI:
		value.emplace(ItemCfg{.label = "value"});
		// absolute timeout
		timeout.emplace(ItemCfg{.label = "timeout"});
		futex2_addr.emplace(make_item_cfg("addr2", "requeue address"));
		addParameters(*value, *timeout, *futex2_addr);
		break;
	default:
		/* unknown operation? keep defaults. */
		break;
	}

	return true;
}

void FutexSystemCall::updateFDTracking(const Tracee &proc) {
	if (new_fd) {
		// we don't even have a type for this, because this feature
		// was dropped in kernel 2.6.26, so I guess it doesn't make
		// sense to track anything here.
		(void)proc;
	}
}

} // end ns
