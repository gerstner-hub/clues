#pragma once

#include <cstdint>

/**
 * @file
 *
 * This provides various kernel typedefs which might be used in kernel struct
 * definitions.
 **/

namespace clues {

	using compat_int_t     =  int32_t;
	using compat_uptr_t    = uint32_t;
	using compat_clock_t   =  int32_t;
	using compat_pid_t     =  int32_t;
	using __compat_uid32_t = uint32_t;
	using compat_timer_t   =  int32_t;
	using compat_ulong_t   = uint32_t;
	using compat_long_t    =  int32_t;
	using compat_size_t    = uint32_t;

	template<typename PTR=void*>
	inline PTR convert_compat_ptr(const compat_uptr_t ptr32) {
		return reinterpret_cast<PTR>(ptr32);
	}

} // end ns
