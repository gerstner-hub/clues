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
#define BITFLAGS_STREAM() _bf_ss
#define BITFLAGS_ADD(FLAG) if (FLAG && (_flags & FLAG) == FLAG) _bf_ss << #FLAG << '|'
#define BITFLAGS_STR() strip_back(_bf_ss.str()) + ")"

} // end ns
