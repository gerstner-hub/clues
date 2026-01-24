#pragma once

// C++
#include <sstream>
#include <string>

// cosmos
#include <cosmos/formatting.hxx>

namespace clues {

inline std::string strip_back(std::string &&s, const char ch = '|') {
	if (s.back() == ch)
		s.pop_back();
	return s;
}

/// helper for constructing a string of bit flags
#define BITFLAGS_FORMAT_START(bitmask) std::stringstream _bf_ss; auto _flags = bitmask.raw(); \
		_bf_ss << cosmos::HexNum<decltype(bitmask)::EnumBaseType>{_flags, 0} << " ("
/// this is used for cases where the original value contains an additional fixed part which is stripped from the bitmask
/**
 * For example in openat() the flags argument contains a fixed part like
 * O_RDWR and a bit mask part. The libcosmos BitMask usually only contains the
 * flags part. For the hex representation we need full value, however, which
 * is passed as `raw_val` to this macro.
 **/
#define BITFLAGS_FORMAT_START_COMBINED(bitmask, raw_val) std::stringstream _bf_ss; \
		auto _flags = bitmask.raw(); \
		_bf_ss << cosmos::HexNum<decltype(raw_val)>{raw_val, 0} << " ("
#define BITFLAGS_STREAM() _bf_ss
#define BITFLAGS_ADD(FLAG) if (FLAG && (_flags & FLAG) == FLAG) _bf_ss << #FLAG << '|'
#define BITFLAGS_STR() strip_back(_bf_ss.str()) + ")"

} // end ns
