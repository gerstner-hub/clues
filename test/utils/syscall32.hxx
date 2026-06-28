// C++
#include <cstring>
#include <format>
#include <type_traits>

// Linux
#include <sys/mman.h>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/sysnrs/generic.hxx>
#include <clues/sysnrs/i386.hxx>

/*
 * this header contains helpers to invoked 32-bit system calls on AMD64
 */

#ifdef COSMOS_X86_64
#	define TEST_I386_EMU

using namespace std::string_literals;

/*
 * syscall() like wrapper for explicitly calling 32-bit emulation system calls
 * in x86-64 context.
 *
 * For testing tracing of 32-bit emulation Tracee's we'd ideally need separate
 * binaries compiled with `-m32`, but this would bloat the unit testing
 * approach massively.
 *
 * Instead we go for a bit of a hacky solution by explicitly invoking 32-bit
 * system calls from our 64-bit child processes. This has a couple of
 * complications as well:
 *
 * - parameters to system calls must not be larger than 32 bits. We verify
 *   this in the wrapper and throw an exception should this happen. We verify
 *   this in the wrapper and throw an exception should this happen.
 * - this also goes for pointers, which means that we need to specially
 *   manager 32-bit memory allocations using `alloc32()`.
 *
 * NOTE: testing the X32 ABI can be done in a similar way. In modern kernels
 * the ABI is disabled by default, however and requires an explicit boot
 * parameter to work. Since this ABI is highly exotic these days it probably
 * doesn't make sense to invest a lot of work into it at the moment.
 */
template <class T1=long, class T2=long, class T3=long, class T4=long, class T5=long, class T6=long>
static int syscall32(const clues::SystemCallNrI386 nr,
		T1 t1=0, T2 t2=0, T3 t3=0, T4 t4=0, T5 t5=0, T6 t6=0) {

	auto fits_in32 = [](long x) -> bool {
		return (long)(int32_t)x == x;
	};

	auto cast_to_long = [](auto in) -> long {
		if constexpr (std::is_arithmetic_v<decltype(in)> || std::is_enum_v<decltype(in)>) {
			return static_cast<long>(in);
		}

		if constexpr (!std::is_arithmetic_v<decltype(in)> && !std::is_enum_v<decltype(in)>) {
			return reinterpret_cast<long>(in);
		}
	};

	long _1 = cast_to_long(t1);
	long _2 = cast_to_long(t2);
	long _3 = cast_to_long(t3);
	long _4 = cast_to_long(t4);
	long _5 = cast_to_long(t5);
	long _6 = cast_to_long(t6);

	if (!fits_in32(_1) || !fits_in32(_2) || !fits_in32(_3) ||
			!fits_in32(_4) || !fits_in32(_5) || !fits_in32(_6)) {
		const auto fit_values = std::format("{} {} {} {} {} {}",
			fits_in32(_1), fits_in32(_2), fits_in32(_3),
			fits_in32(_4), fits_in32(_5), fits_in32(_6));
		throw cosmos::RuntimeError{"too large syscall32 parameters: "s + fit_values};
	}

	register long eax asm("eax") = cosmos::to_integral(nr);
	register long ebx asm("ebx") = _1;
	register long ecx asm("ecx") = _2;
	register long edx asm("edx") = _3;
	register long esi asm("esi") = _4;
	register long edi asm("edi") = _5;

	asm volatile(
			"push %%rbp\n\t"
			"mov %[_6], %%rbp\n\t"
			"int $0x80\n\t"
			"pop %%rbp"
			: "+r"(eax)
			: "r"(ebx), "r"(ecx), "r"(edx),
			"r"(esi), "r"(edi), [_6]"r"(_6)
			: "memory"
	);

	return eax;
}

template <typename T>
static T alloc32(size_t bytes) {
	auto ret = mmap(nullptr, bytes, PROT_READ|PROT_WRITE, MAP_32BIT|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (ret == MAP_FAILED) {
		throw cosmos::ApiError{"mmap()[32]"};
	}

	return reinterpret_cast<T>(ret);
}

template <typename T>
static T* alloc_struct32() {
	return alloc32<T*>(sizeof(T));
}

const char* alloc_str32(const char *s) {
	const auto len = std::strlen(s) + 1;
	auto ret = alloc32<char*>(len);
	std::strcpy(ret, s);
	return ret;
}
#endif // COSMOS_X86_64

#ifdef TEST_I386_EMU
#	define I386_CROSS_ABI(IGNORE_COUNT, ...) ExtraABI{ \
		clues::ABI::I386, \
		IGNORE_COUNT, \
		__VA_ARGS__ \
	}

using SyscallNr32 = clues::SystemCallNrI386;

#else
#	define I386_CROSS_ABI(IGNORE_COUNT, ...)
#endif
