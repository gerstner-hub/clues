// test
#include "utils/syscalls.hxx"

namespace {

const auto TESTS = std::array{
	TestSpec{SystemCallNr::GETRANDOM, []() {
			uint8_t buf[16];
			syscall(SYS_getrandom, buf, 16, GRND_NONBLOCK);
		}, ENTRY_VERIFY_CB(GetRandomSystemCall, {
			VERIFY(sc.count.value() == 16);
			VERIFY(sc.flags.flags() == cosmos::GetRandomFlags{cosmos::GetRandomFlag::NONBLOCK});
		}), EXIT_VERIFY_CB(GetRandomSystemCall, {
			/* we need to consider the situation that the kernel
			 * couldn't provide all data or any at all. */
			if (sc.hasResultValue()) {
				VERIFY(sc.obtained.value() > 0 && sc.obtained.value() <= 16);
			} else {
				VERIFY(sc.error()->errorCode() == cosmos::Errno::AGAIN);
			}
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				const auto *buffer = alloc32<uint8_t*>(16);
				syscall32(SyscallNr32::GETRANDOM, buffer, 16, GRND_NONBLOCK);
			})
		}
	},
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
