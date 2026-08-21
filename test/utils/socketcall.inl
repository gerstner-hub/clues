#pragma once

#include <cstdint>

// cosmos
#include <cosmos/compiler.hxx>

// test
#include "syscall32.hxx"

namespace {

/*
 * there are wrappers to simplify invocation of the socketcall() multiplexed
 * socket API.
 */

// `unsigned long` on I386, this here works also in emulation context
using socketcall_t = uint32_t;

template <typename T>
unsigned long to_socketcall_arg(T value) {
    if constexpr (std::is_pointer_v<T>) {
        return static_cast<socketcall_t>(reinterpret_cast<uintptr_t>(value));
    } else {
        return static_cast<socketcall_t>(value);
    }
}

template <typename... ARGS>
requires (sizeof...(ARGS) <= 6)
std::array<socketcall_t, sizeof...(ARGS)> make_array(ARGS... args) {
    std::array<socketcall_t, sizeof...(ARGS)> result{};

    std::size_t i = 0;
    ((result[i++] = to_socketcall_arg(args)), ...);

    return result;
}

#ifdef COSMOS_I386

template <typename... ARGS>
int socketcall(int call, ARGS... args) {
	const auto arr = make_array(std::forward<ARGS>(args)...);

	return syscall(SYS_socketcall, call, arr.data());
}

#else

template <typename... ARGS>
int socketcall32(int call, ARGS... args) {
	const auto arr = make_array(std::forward<ARGS>(args)...);

	constexpr auto ARR_BYTES = arr.size() * sizeof(socketcall_t);
	auto arr32 = alloc32<socketcall_t*>(ARR_BYTES);
	std::memcpy(arr32, arr.data(), ARR_BYTES);

	return syscall32(SyscallNr32::SOCKETCALL, call, arr32);
}

#endif

} // end anon ns
