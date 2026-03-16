// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/futex.hxx>
#include <clues/macros.h>
#include <clues/private/utils.hxx>

namespace clues::item {

std::string FutexOperation::str() const {
	/*
	 * there are a number of undocumented constants and some flags can be
	 * or'd in like FUTEX_PRIVATE_FLAG. Without exactly understanding that
	 * we can't sensibly trace this ...
	 * it seems the man page doesn't tell the complete story, strace
	 * understands all the "private" stuff that can also be found in the
	 * header.
	 */
	auto format_op = [](int val) -> std::string {
		switch (val & FUTEX_CMD_MASK) {
			CASE_ENUM_TO_STR(FUTEX_CMP_REQUEUE);
			CASE_ENUM_TO_STR(FUTEX_CMP_REQUEUE_PI);
			CASE_ENUM_TO_STR(FUTEX_FD);
			CASE_ENUM_TO_STR(FUTEX_LOCK_PI);
			CASE_ENUM_TO_STR(FUTEX_LOCK_PI2);
			CASE_ENUM_TO_STR(FUTEX_REQUEUE);
			CASE_ENUM_TO_STR(FUTEX_TRYLOCK_PI);
			CASE_ENUM_TO_STR(FUTEX_UNLOCK_PI);
			CASE_ENUM_TO_STR(FUTEX_WAIT);
			CASE_ENUM_TO_STR(FUTEX_WAIT_BITSET);
			CASE_ENUM_TO_STR(FUTEX_WAIT_REQUEUE_PI);
			CASE_ENUM_TO_STR(FUTEX_WAKE);
			CASE_ENUM_TO_STR(FUTEX_WAKE_BITSET);
			CASE_ENUM_TO_STR(FUTEX_WAKE_OP);
			default: return cosmos::sprintf("unknown (%d)", val);
		}
	};

	const auto val = valueAs<int>();
	BITFLAGS_FORMAT_START_COMBINED(m_flags, val);

	BITFLAGS_STREAM() << format_op(val);

	if (!m_flags.none()) {
		BITFLAGS_STREAM() << '|';
		BITFLAGS_ADD(FUTEX_PRIVATE_FLAG);
		BITFLAGS_ADD(FUTEX_CLOCK_REALTIME);
	}

	return BITFLAGS_STR();
}

void FutexOperation::processValue(const Tracee &) {
	m_cmd = Command{valueAs<int>() & FUTEX_CMD_MASK};
	m_flags = Flags{valueAs<int>() xor cosmos::to_integral(m_cmd)};
}

namespace {

std::string get_label(const FutexWakeOperation::Operation op) {
	switch (cosmos::to_integral(op)) {
		CASE_ENUM_TO_STR(FUTEX_OP_SET);
		CASE_ENUM_TO_STR(FUTEX_OP_ADD);
		CASE_ENUM_TO_STR(FUTEX_OP_OR);
		CASE_ENUM_TO_STR(FUTEX_OP_ANDN);
		CASE_ENUM_TO_STR(FUTEX_OP_XOR);
		default: return cosmos::sprintf("unknown (%d)", cosmos::to_integral(op));
	}
}

std::string get_label(const FutexWakeOperation::Comparator cmp) {
	switch (cosmos::to_integral(cmp)) {
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_EQ);
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_NE);
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_LT);
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_LE);
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_GT);
		CASE_ENUM_TO_STR(FUTEX_OP_CMP_GE);
		default: return cosmos::sprintf("unknown (%d)", cosmos::to_integral(cmp));
	}
}

}

void FutexWakeOperation::processValue(const Tracee &) {
	const auto raw = valueAs<uint32_t>();
	/*
	 * the integer is structured like this:
	 *
	 * <4 bits Operation><4 bits Comparator><12 bits oparg><12 bits cmparg>
	 *
	 * where the upper bit of the operation is the optional "shift arg"
	 * flag.
	 */

	const auto op_bits = raw >> 28;
	/*
	 * NOTE: there's a bug in man futex(2), which names FUTEX_OP_ARG_SHIFT
	 * here instead.
	 */
	m_op = Operation{op_bits & (~FUTEX_OP_OPARG_SHIFT)};
	m_shift_arg = op_bits & FUTEX_OP_OPARG_SHIFT;
	m_comp = Comparator{(raw >> 24) & 0xF};
	m_oparg = (raw >> 12) & 0xFFF;
	m_cmparg = raw & 0xFFF;

}

std::string FutexWakeOperation::str() const {
	return cosmos::sprintf("{op=%s%s, cmp=%s, oparg=%u, cmparg=%u}",
		get_label(m_op).c_str(),
		m_shift_arg ? "|FUTEX_OP_OPARG_SHIFT" : "",
		get_label(m_comp).c_str(),
		m_oparg,
		m_cmparg);
}

} // end ns
