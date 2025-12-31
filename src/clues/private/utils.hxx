#pragma once

namespace clues {

inline std::string strip_back(std::string &&s, const char ch = '|') {
	if (s.back() == ch)
		s.pop_back();
	return s;
}

/// helper for constructing a string of bit flags
#define add_bitflag(FLAG) if (FLAG && (flags & FLAG) == FLAG) ss << #FLAG << '|';
#define get_bitflags() strip_back(ss.str());

} // end ns
