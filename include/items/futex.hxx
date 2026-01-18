#pragma once

// Linux
#include <linux/futex.h> // futex(2)

// cosmos
#include <cosmos/BitMask.hxx>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// The futex operation to be performed in the context of a futex system call.
/**
 * The operation consists of a command and a set of bit mask flags.
 **/
class CLUES_API FutexOperation :
		public ValueInParameter {
public: // types

	enum class Command : int {
		WAIT            = FUTEX_WAIT, /* wait for `val` to be changed */
		WAKE            = FUTEX_WAKE, /* wake given number of waiters */
		WAIT_REQUEUE_PI = FUTEX_WAIT_REQUEUE_PI, /* wait on a non-PI futex, potentially being requeued to a PI futex on addr2 */
		CREATE_FD       = FUTEX_FD, /* create a futex FD, dropped in Linux 2.6.25 */
		REQUEUE         = FUTEX_REQUEUE, /* wakeup some waiters, requeue others */
		CMP_REQUEUE     = FUTEX_CMP_REQUEUE, /* additionally compare futex value */
		CMP_REQUEUE_PI  = FUTEX_CMP_REQUEUE_PI, /* CMP_REQUEUE with priority-inheritance semantics. `val1` must be 1. */
		WAKE_OP         = FUTEX_WAKE_OP, /* wake up waiters based on provided criteria */
		WAIT_BITSET     = FUTEX_WAIT_BITSET, /* wait based on a 32-bit bitset limiting wakeups */
		WAKE_BITSET     = FUTEX_WAKE_BITSET, /* wake up waiters with matching bits in a 32-bit bitset */
		LOCK_PI         = FUTEX_LOCK_PI, /* priority-inheritance lock operation */
		LOCK_PI2        = FUTEX_LOCK_PI2, /* save as above, but supports Flag::REALTIME on top */
		TRYLOCK_PI      = FUTEX_TRYLOCK_PI, /* try to lock the futex based on extra kernel information, does not block */
		UNLOCK_PI       = FUTEX_UNLOCK_PI, /* unlock with priority inheritance semantics */
	};

	enum class Flag : int {
		PRIVATE_FLAG = FUTEX_PRIVATE_FLAG, /* futex between threads only */
		REALTIME = FUTEX_CLOCK_REALTIME, /* for wait related operations, use CLOCK_REALTIME instead of MONOTONIC */
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	explicit FutexOperation() :
			ValueInParameter{"op", "futex operation"} {
	}

	std::string str() const override;

	void processValue(const Tracee &) override;

	auto command() const {
		return m_cmd;
	}

	auto flags() const {
		return m_flags;
	}

protected: // data

	Command m_cmd = Command{0};
	Flags m_flags;
};

/// Composite bit values used in `val3` for `futex()` operation FUTEX_WAKE_OP.
/**
 * This parameter defines scalar operations and comparisons to be carried out
 * in the context of FutexOperation::Command::WAKE_OP.
 *
 * The futex value found at `uaddr2` is modified based on the given
 * `Operation` and the result is written back to the futex in an atomic
 * fashion.
 *
 * The waiters blocked on `uaddr` are woken up.
 *
 * The original futex value observed at `uaddr2` is additionally compared
 * based on the given `Comparator`. If the comparison yields `true` then a
 * number of waiters blocked on `uaddr2` are also woken up.
 *
 * The information to the `uaddr2` modification and comparison is stored in a
 * uint32_t passed to the futex system call, whose details are made available
 * in this type..
 **/
class CLUES_API FutexWakeOperation :
		public ValueInParameter {
public: // types

	/// Atomic operation to be carried out on futex value.
	enum class Operation : uint32_t {
		SET  = FUTEX_OP_SET,  ///< assignment `uaddr2 = oparg`
		ADD  = FUTEX_OP_ADD,  ///< addition `uaddr2 += oparg`
		OR   = FUTEX_OP_OR,   ///< bitwise or `uaddr2 |= oparg`
		ANDN = FUTEX_OP_ANDN, ///< bitwise and of negated value `uaddr2 &= ~oparg`
		XOR  = FUTEX_OP_XOR,  ///< bitwise XOR `uaddr ^= oparg`
	};

	enum class Comparator : uint32_t {
		EQUAL         = FUTEX_OP_CMP_EQ,  ///< `oldval == cmparg`
		UNEQUAL       = FUTEX_OP_CMP_NE, ///< `oldval != cmparg`
		LESS_THAN     = FUTEX_OP_CMP_LT,  ///< `oldval < cmparg`
		LESS_EQUAL    = FUTEX_OP_CMP_LE,  ///< `oldval <= cmparg`
		GREATER_THAN  = FUTEX_OP_CMP_GT,  ///< `oldval > cmparg`
		GREATER_EQUAL = FUTEX_OP_CMP_GE,  ///< `oldval >= cmparg`
	};

public: // functions

	explicit FutexWakeOperation() :
			ValueInParameter{"wake_op", "wake operation settings"} {
	}

	std::string str() const override;

	void processValue(const Tracee &) override;

	auto operation() const {
		return m_op;
	}

	auto comparator() const {
		return m_comp;
	}

	bool doShiftArg() const {
		return m_shift_arg;
	}

	uint32_t oparg() const {
		return m_oparg;
	}

	uint32_t cmparg() const {
		return m_cmparg;
	}

protected: // data

	Operation m_op = Operation{0};
	Comparator m_comp = Comparator{0};
	///! Whether `oparg` is additionally replaced by `1 << oparg`.
	bool m_shift_arg = false;
	///! The operation argument used in `uaddr2 OP oparg`.
	uint32_t m_oparg = 0;
	///! The comparison argument used in `oldval CMP cmparg`.
	uint32_t m_cmparg = 0;
};

} // end ns
