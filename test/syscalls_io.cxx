// test
#include "syscalls/io.hxx"
#include "utils/syscalls.hxx"

// Linux
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

// clues
#include <clues/private/kernel/time.hxx>
#include <clues/private/kernel/select.hxx>
#include <clues/private/kernel/sigset.hxx>

// test
#include <utils/types.hxx>

namespace {

using ABI = clues::ABI;

void call_newselect(const int sysnr) {
	int fd[2];
	if (pipe(fd) < 0) {
		return;
	}

	int readfd = fd[0];
	int writefd = fd[1];
	/* test the highest fdset bit */
	writefd = dup2(writefd, 1023);

	fd_set readset, writeset;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);

	canon_timeval tv;
	tv.tv_sec = 50;
	tv.tv_usec = 100;
	syscall(sysnr, writefd + 1,
			&readset, &writeset, nullptr, &tv);
}

template <class TIMESPEC=canon_timespec>
void call_pselect(const int sysnr=SYS_pselect6) {
	int fd[2];
	if (pipe(fd) < 0) {
		return;
	}

	int readfd = fd[0];
	int writefd = fd[1];
	writefd = dup2(writefd, 1023);

	fd_set readset, writeset;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);

	TIMESPEC ts;
	ts.tv_sec = 50;
	ts.tv_nsec = 100;
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGINT);
	clues::sigset_argpack pack;
	pack.sigset_p = &mask;
	pack.size = 8;
	syscall(sysnr, writefd + 1, &readset, &writeset, nullptr, &ts, &pack);
}

#ifdef TEST_I386_EMU
template <class TIMESPEC=struct timespec>
void call_pselect32(const SyscallNr32 nr = SyscallNr32::PSELECT6) {
	int fd[2];
	if (pipe(fd) < 0) {
		return;
	}

	int readfd = fd[0];
	int writefd = fd[1];
	writefd = dup2(writefd, 1023);

	auto readset = alloc_struct32<fd_set>();
	auto writeset = alloc_struct32<fd_set>();;

	FD_SET(readfd, readset);
	FD_SET(writefd, writeset);

	auto ts32 = alloc_struct32<TIMESPEC>();
	ts32->tv_sec = 50;
	ts32->tv_nsec = 100;

	auto ss = alloc_struct32<sigset_t>();
	sigemptyset(ss);
	sigaddset(ss, SIGINT);
	sigaddset(ss, SIGQUIT);

	auto pack = alloc_struct32<clues::sigset_argpack32>();
	pack->sigset_p = (uint32_t)(uintptr_t)ss;
	pack->size = 8;

	syscall32(nr, writefd + 1, readset, writeset, NULL, ts32, pack);
}
#endif

void verify_select_base_entry(const clues::SelectSystemCallBase &sc, bool &good) {
	VERIFY(sc.nfds.value() == 1024);
	VERIFY(sc.readfds.requestSet().has_value());
	VERIFY(!sc.readfds.eventSet().has_value());
	VERIFY(sc.writefds.requestSet().has_value());
	VERIFY(!sc.writefds.eventSet().has_value());
	VERIFY(!sc.exceptfds.requestSet().has_value());
	VERIFY(!sc.exceptfds.eventSet().has_value());
	const auto &readset = *sc.readfds.requestSet();
	const auto &writeset = *sc.writefds.requestSet();

	VERIFY(readset.isSet(FIRST_FD));
	VERIFY(!readset.isSet(SECOND_FD));
	VERIFY(!writeset.isSet(SECOND_FD));
	VERIFY(!writeset.isSet(FIRST_FD));
	VERIFY(writeset.isSet(cosmos::FileNum{1023}));
}

void verify_select_entry(const clues::SelectSystemCall &sc, bool &good,
		bool is_old_select=false) {
	verify_select_base_entry(sc, good);
	VERIFY(sc.old_args.has_value() == is_old_select);
	VERIFY(sc.timeout.val().has_value());
	VERIFY(!sc.timeout.remaining().has_value());
	const auto &tv = *sc.timeout.val();
	VERIFY(tv.tv_sec == 50);
	VERIFY(tv.tv_usec == 100);
}

void verify_select_base_exit(const clues::SelectSystemCallBase &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.readfds.requestSet().has_value());
	VERIFY(sc.readfds.eventSet().has_value());
	VERIFY(sc.writefds.requestSet().has_value());
	VERIFY(sc.writefds.eventSet().has_value());
	VERIFY(!sc.exceptfds.requestSet().has_value());
	VERIFY(!sc.exceptfds.eventSet().has_value());
	const auto &readset = *sc.readfds.eventSet();
	const auto &writeset = *sc.writefds.eventSet();

	VERIFY(!readset.isSet(FIRST_FD));
	VERIFY(!readset.isSet(SECOND_FD));
	VERIFY(!writeset.isSet(SECOND_FD));
	VERIFY(!writeset.isSet(FIRST_FD));
	VERIFY(writeset.isSet(cosmos::FileNum{1023}));
}

void verify_select_exit(const clues::SelectSystemCall &sc, bool &good,
		bool is_old_select=false) {
	verify_select_base_exit(sc, good);
	VERIFY(sc.old_args.has_value() == is_old_select);

	VERIFY(sc.timeout.val().has_value());
	VERIFY(sc.timeout.remaining().has_value());
}

void verify_pselect_entry(const clues::PSelectSystemCall &sc, bool &good) {
	verify_select_base_entry(sc, good);
	VERIFY(sc.timeout.spec().has_value());
	VERIFY(!sc.timeout.remaining().has_value());
	const auto &ts = *sc.timeout.spec();
	VERIFY(ts.tv_sec == 50);
	VERIFY(ts.tv_nsec == 100);
	VERIFY(sc.sigmask.sigset().has_value());
	const auto &set = *sc.sigmask.sigset();
	VERIFY(set.isSet(cosmos::signal::INTERRUPT));
	VERIFY(set.isSet(cosmos::signal::QUIT));
	VERIFY(!set.isSet(cosmos::signal::SEGV));
}

void verify_pselect_exit(const clues::PSelectSystemCall &sc, bool &good) {
	verify_select_base_exit(sc, good);
	VERIFY(sc.timeout.spec().has_value());
	VERIFY(sc.timeout.remaining().has_value());
}

const auto TESTS = std::array{

	TestSpec{SystemCallNr::IOCTL, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			int attr;
			ioctl(fd, FS_IOC_GETFLAGS, &attr);
		}, ENTRY_VERIFY_CB(IoCtlSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.request.value() == FS_IOC_GETFLAGS);
		}), EXIT_VERIFY_CB(IoCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto attr = alloc32<int*>(sizeof(int));
				/* this has the highest bit set, avoid any
				 * surprises by explicitly forcing it into an
				 * int32_t */
				constexpr int32_t flags = FS_IOC_GETFLAGS;
				syscall32(SyscallNr32::IOCTL, fd, flags, attr);
			})}
	}, TestSpec{SystemCallNr::READ, []() {
			int fd = open("/etc/fstab", O_RDONLY);
			char buffer[1024];
			if (read(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
		}), EXIT_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.buf.availableBytes() > 0);
			VERIFY(sc.buf.data().size() <= sc.buf.availableBytes());
			VERIFY(sc.read.value() == sc.buf.availableBytes());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto path = alloc_str32("/etc/fstab");
				int fd = open(path, O_RDONLY);
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::READ, fd, buffer, 1024) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::READ, []() {
			int pipes[2];
			if (pipe2(pipes, O_NONBLOCK) < 0) {

			}
			char buffer[1024];
			if (read(pipes[0], buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
		}), EXIT_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.hasErrorCode());
			VERIFY(sc.buf.availableBytes() == 0);
			VERIFY(sc.buf.data().empty());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, O_NONBLOCK) < 0) {
				}
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::READ, pipes[0], buffer, 1024) < 0) {
				}
			})
		},
		"failed read"
	}, TestSpec{SystemCallNr::READV, []() {
			int pipes[2];
			if (pipe2(pipes, 0) < 0) {

			}

			constexpr std::string_view DATA{"test"};

			if (::write(pipes[1], DATA.data(), DATA.size()) != DATA.size()) {

			}

			char buf1[128];
			char buf2[200];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::readv(pipes[0], vec,
						sizeof(vec) / sizeof(struct iovec)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 128);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 200);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
		}), EXIT_VERIFY_CB(ReadVSystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 4);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.read.value() == 4);
			const std::string_view data{(const char*)buffers[0].data.data(), buffers[0].data.size()};
			VERIFY(data == "test");
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, 0) < 0) {
				}
				auto buf1 = alloc32<char*>(128);
				auto buf2 = alloc32<char*>(200);
				auto data = alloc_str32("test");
				if (write(pipes[1], data, 4) != 4) {

				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 128;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 200;
				if (syscall32(SyscallNr32::READV, pipes[0], vec, 2) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::READV, []() {
			int pipes[2];
			if (pipe2(pipes, O_NONBLOCK) < 0) {

			}

			char buf1[128];
			char buf2[200];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::readv(pipes[0], vec,
						sizeof(vec) / sizeof(struct iovec)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 128);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 200);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
		}), EXIT_VERIFY_CB(ReadVSystemCall, {
			VERIFY(sc.hasErrorCode());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.read.value() == 0);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, O_NONBLOCK) < 0) {
				}
				auto buf1 = alloc32<char*>(128);
				auto buf2 = alloc32<char*>(200);

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 128;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 200;
				if (syscall32(SyscallNr32::READV, pipes[0], vec, 2) < 0) {
				}
			})
		},
		"failed read"
	}, TestSpec{SystemCallNr::PREADV, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			constexpr std::string_view DATA{"test data for positioned vector read"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			char buf1[10];
			char buf2[20];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::preadv(fd, vec, sizeof(vec) / sizeof(struct iovec), 5) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 10);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 20);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 5);
		}), EXIT_VERIFY_CB(PReadVSystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 10);
			VERIFY(buffers[1].filled == 20);
			VERIFY(sc.read.value() == 30);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				auto buf1 = alloc32<char*>(10);
				auto buf2 = alloc32<char*>(20);
				auto data = alloc_str32("test data for positioned vector read");
				const ssize_t len = strlen(data);
				if (write(fd, data, len) != len) {
					return;
				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 10;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 20;
				if (syscall32(SyscallNr32::PREADV, fd, vec, 2, 5, 0) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PREADV, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			char buf[64];
			struct iovec vec;
			vec.iov_base = (void*)buf;
			vec.iov_len = sizeof(buf);
			if (::preadv(fd, &vec, 1, LARGE_OFFSET64) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadVSystemCall, {
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
		}), EXIT_VERIFY_CB(PReadVSystemCall, {
			(void)sc;
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

				auto buf = alloc32<char*>(20);
				auto vec = alloc_struct32<clues::iovec32>();
				vec->iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf));
				vec->iov_len = 20;
				/* large offset composed of 1 high bit and one low bit */
				if (syscall32(SyscallNr32::PREADV, fd, vec, 1, 2, 1) < 0) {
				}
			})
		}, "64-bit offset"
	}, TestSpec{SystemCallNr::PREADV2, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			constexpr std::string_view DATA{"test data for positioned vector read"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			char buf1[10];
			char buf2[20];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::preadv2(fd, vec, sizeof(vec) / sizeof(struct iovec), 5, RWF_HIPRI) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadV2SystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 10);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 20);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 5);
			VERIFY(sc.flags.flags() == cosmos::StreamIO::ReadWriteFlag::HIGH_PRIO);
		}), EXIT_VERIFY_CB(PReadV2SystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 10);
			VERIFY(buffers[1].filled == 20);
			VERIFY(sc.read.value() == 30);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				auto buf1 = alloc32<char*>(10);
				auto buf2 = alloc32<char*>(20);
				auto data = alloc_str32("test data for positioned vector read");
				const ssize_t len = strlen(data);
				if (write(fd, data, len) != len) {
					return;
				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 10;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 20;
				if (syscall32(SyscallNr32::PREADV2, fd, vec, 2, 5, 0, RWF_HIPRI) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::WRITE, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			const char buffer[] = "abcdefgh";
			if (write(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(WriteSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.buf.data().size() == 9);
			std::string s;
			for (const auto byte: sc.buf.data()) {
				const auto ch = static_cast<char>(byte);
				if (ch)
					s.push_back(ch);
			}
			VERIFY(s == "abcdefgh");
			VERIFY(sc.count.value() == 9);
			VERIFY(sc.buf.availableBytes() == 9);
		}), EXIT_VERIFY_CB(WriteSystemCall, {
			VERIFY(sc.hasResultValue());
			// partial writes should not occur here
			VERIFY(sc.written.value() == 9);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buffer = alloc_str32("abcdefgh");
				syscall32(SyscallNr32::WRITE, fd, buffer, strlen(buffer) + 1);
			})
		}
	}, TestSpec{SystemCallNr::WRITEV, []() {
			int pipes[2];
			if (pipe2(pipes, 0) < 0) {

			}

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::writev(pipes[1], vec, sizeof(vec) / sizeof(struct iovec)) != DATA1.size() + DATA2.size()) {

			}

		}, ENTRY_VERIFY_CB(WriteVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == SECOND_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			const std::string_view data1{(const char*)buffers[0].data.data(), buffers[0].data.size()};
			const std::string_view data2{(const char*)buffers[1].data.data(), buffers[1].data.size()};
			VERIFY(data1 == "test1");
			VERIFY(data2 == "test20");
		}), EXIT_VERIFY_CB(WriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, 0) < 0) {
				}
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::WRITEV, pipes[1], vec, 2) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITEV, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::pwritev(fd, vec, sizeof(vec) /
						sizeof(struct iovec), 15) != DATA1.size() + DATA2.size()) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 15);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::PWRITEV, fd, vec, 2, 15, 0) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITEV, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};

			struct iovec vec;
			vec.iov_base = (void*)DATA1.data();
			vec.iov_len = DATA1.size();

			if (::pwritev(fd, &vec, 1, LARGE_OFFSET64) < 0) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			(void)sc;
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");

				auto vec = alloc_struct32<clues::iovec32>();
				vec->iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec->iov_len = 5;
				/* 64-bit offset comprised of 1 high bit and 1 low bit */
				if (syscall32(SyscallNr32::PWRITEV, fd, vec, 1, 2, 1) < 0) {
				}
			})
		}, "64-bit offset"
	}, TestSpec{SystemCallNr::PWRITEV2, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::pwritev2(fd, vec, sizeof(vec) / sizeof(struct iovec), 15, RWF_HIPRI) != DATA1.size() + DATA2.size()) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteV2SystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 15);
			VERIFY(sc.flags.flags() == cosmos::StreamIO::ReadWriteFlag::HIGH_PRIO);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::PWRITEV2, fd, vec, 2, 15, 0, RWF_HIPRI) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PREAD64, []() {
			int fd = open("/etc/fstab", O_RDONLY);
			char buffer[1024];
			if (pread(fd, buffer, sizeof(buffer), 100) < 0) {

			}
		}, ENTRY_VERIFY_CB(PRead64SystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
			VERIFY(sc.offset.value() == 100);
		}), EXIT_VERIFY_CB(PRead64SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.buf.availableBytes() > 0);
			VERIFY(sc.buf.data().size() <= sc.buf.availableBytes());
			VERIFY(sc.read.value() == sc.buf.availableBytes());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto path = alloc_str32("/etc/fstab");
				int fd = open(path, O_RDONLY);
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::PREAD64, fd, buffer, 1024, 100) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITE64, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			const char buffer[] = "abcdefgh";
			if (write(fd, buffer, sizeof(buffer)) < 0) {

			}
			if (pwrite(fd, buffer, sizeof(buffer), sizeof(buffer) / 2) < 0) {

			}
		}, ENTRY_VERIFY_CB(PWrite64SystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.buf.data().size() == 9);
			std::string s;
			for (const auto byte: sc.buf.data()) {
				const auto ch = static_cast<char>(byte);
				if (ch)
					s.push_back(ch);
			}
			VERIFY(s == "abcdefgh");
			VERIFY(sc.count.value() == 9);
			VERIFY(sc.buf.availableBytes() == 9);
			VERIFY(sc.offset.value() == (off_t)sc.count.value() / 2);
		}), EXIT_VERIFY_CB(PWrite64SystemCall, {
			VERIFY(sc.hasResultValue());
			// partial writes should not occur here
			VERIFY(sc.written.value() == 9);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buffer = alloc_str32("abcdefgh");
				syscall32(SyscallNr32::WRITE, fd, buffer, strlen(buffer) + 1);
				syscall32(SyscallNr32::PWRITE64, fd, buffer, strlen(buffer) + 1, (strlen(buffer) + 1) / 2);
			})
		}
	}, TestSpec{SystemCallNr::LSEEK, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			constexpr std::string_view DATA{"arbitrary data for testing lseek"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			syscall(SYS_lseek, fd, -10L, SEEK_END);
		}, ENTRY_VERIFY_CB(LSeekSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset.value() == -10);
			VERIFY(sc.whence.type() == cosmos::StreamIO::SeekType::END);
		}), EXIT_VERIFY_CB(LSeekSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_offset.value() == 22);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				constexpr std::string_view DATA{"arbitrary data for testing lseek"};
				if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
					return;
				}

				syscall32(SyscallNr32::LSEEK, fd, -10L, SEEK_END);
			})
		},
	}, TestSpec{SystemCallNr::LLSEEK, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			constexpr std::string_view DATA{"arbitrary data for testing lseek"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			/* this will automatically be translated into llseek() by glibc */
			lseek(fd, LARGE_OFFSET64, SEEK_SET);
		}, ENTRY_VERIFY_CB(LLSeekSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
			VERIFY(sc.whence.type() == cosmos::StreamIO::SeekType::SET);
		}), EXIT_VERIFY_CB(LLSeekSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				constexpr std::string_view DATA{"arbitrary data for testing lseek"};
				if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
					return;
				}

				auto new_off = alloc_struct32<off_t>();

				syscall32(SyscallNr32::LLSEEK, fd, 1, 2, new_off, SEEK_SET);
			})
		}, "", {ABI::I386}
	},
#ifdef CLUES_HAVE_PIPE1
	TestSpec{SystemCallNr::PIPE, []() {
			int pipes[2];
			TWICE({
				syscall(SYS_pipe, pipes);
				close(pipes[0]);
				close(pipes[1]);
			});
		}, ENTRY_VERIFY_CB(PipeSystemCall, {
			VERIFY(sc.ends.readEnd() == cosmos::FileNum::INVALID);
			VERIFY(sc.ends.writeEnd() == cosmos::FileNum::INVALID);
		}), EXIT_VERIFY_CB(PipeSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ends.readEnd() == FIRST_FD);
			VERIFY(sc.ends.writeEnd() == SECOND_FD);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				TWICE({
					syscall32(SyscallNr32::PIPE, pipes);
					close(pipes[0]);
					close(pipes[1]);
				});
			})
		}
	},
#endif
	TestSpec{SystemCallNr::PIPE2, []() {
			int pipes[2];
			TWICE({
				if (pipe2(pipes, O_CLOEXEC|O_NONBLOCK) < 0) {
					_exit(1);
				}
				close(pipes[0]);
				close(pipes[1]);
			});
		}, ENTRY_VERIFY_CB(Pipe2SystemCall, {
			VERIFY(sc.ends.readEnd() == cosmos::FileNum::INVALID);
			VERIFY(sc.ends.writeEnd() == cosmos::FileNum::INVALID);
			const auto flags = sc.flags.flags();
			using enum clues::item::PipeFlags::Flag;
			VERIFY(flags == clues::item::PipeFlags::Flags{CLOEXEC, NONBLOCK});
		}), EXIT_VERIFY_CB(Pipe2SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ends.readEnd() == FIRST_FD);
			VERIFY(sc.ends.writeEnd() == SECOND_FD);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				TWICE({
					syscall32(SyscallNr32::PIPE2, pipes, O_CLOEXEC|O_NONBLOCK);
					close(pipes[0]);
					close(pipes[1]);
				});
			})
		}
	},
#ifdef SYS_eventfd
	TestSpec{SystemCallNr::EVENTFD, []() {
			int fd = syscall(SYS_eventfd, 14);
			close(fd);
		}, ENTRY_VERIFY_CB(EventFDSystemCall, {
			VERIFY(sc.initval.value() == 14);
		}), EXIT_VERIFY_CB(EventFDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				int fd = syscall32(SyscallNr32::EVENTFD, 14);
				close(fd);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::EVENTFD2, []() {
			int fd = eventfd(14, EFD_CLOEXEC);
			close(fd);
		}, ENTRY_VERIFY_CB(EventFD2SystemCall, {
			VERIFY(sc.initval.value() == 14);
			VERIFY(sc.flags.flags() == cosmos::EventFile::Flag::CLOSE_ON_EXEC);
		}), EXIT_VERIFY_CB(EventFDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				int fd = syscall32(SyscallNr32::EVENTFD2, 14, EFD_CLOEXEC);
				close(fd);
			})
		}
	},
#ifdef SYS_select
	/* new select on non-legacy ABIs */
	TestSpec{SystemCallNr::SELECT, []() {
			call_newselect(SYS_select);
		}, ENTRY_VERIFY_CB(SelectSystemCall, {
			verify_select_entry(sc, good);
		}), EXIT_VERIFY_CB(SelectSystemCall, {
			verify_select_exit(sc, good);
		}), IgnoreCalls{2}, {
		}, "", {ABI::X86_64, ABI::AARCH64}
	},
	/* new select on legacy ABIs */
	TestSpec{SystemCallNr::NEWSELECT, []() {
#ifdef COSMOS_I386
			call_newselect(SYS__newselect);
#endif
		}, ENTRY_VERIFY_CB(SelectSystemCall, {
			verify_select_entry(sc, good);
		}), EXIT_VERIFY_CB(SelectSystemCall, {
			verify_select_exit(sc, good);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				int fd[2];
				if (pipe(fd) < 0) {
					return;
				}

				int readfd = fd[0];
				int writefd = fd[1];
				writefd = dup2(writefd, 1023);

				auto readset = alloc_struct32<fd_set>();
				auto writeset = alloc_struct32<fd_set>();;

				FD_ZERO(readset);
				FD_ZERO(writeset);

				FD_SET(readfd, readset);
				FD_SET(writefd, writeset);

				auto tv = alloc_struct32<clues::timeval32>();
				tv->tv_sec = 50;
				tv->tv_usec = 100;
				syscall32(SyscallNr32::NEWSELECT, writefd + 1,
						readset, writeset, nullptr, tv);
				}
		)}, "", {ABI::I386}
	},
	/* old select on legacy ABIs */
	TestSpec{SystemCallNr::SELECT, []() {
#	ifdef COSMOS_I386
			int fd[2];
			if (pipe(fd) < 0) {
				return;
			}

			int readfd = fd[0];
			int writefd = fd[1];
			writefd = dup2(writefd, 1023);

			fd_set readset, writeset;

			FD_ZERO(&readset);
			FD_ZERO(&writeset);

			FD_SET(readfd, &readset);
			FD_SET(writefd, &writeset);

			canon_timeval tv;
			tv.tv_sec = 50;
			tv.tv_usec = 100;
			clues::select_arg_struct args;

			args.nfds = writefd + 1;
			args.readset_p = reinterpret_cast<uint32_t>(&readset);
			args.writeset_p = reinterpret_cast<uint32_t>(&writeset);
			args.exceptset_p = 0;
			args.timeval_p = reinterpret_cast<uint32_t>(&tv);

			syscall(SYS_select, &args);
#	endif // I386
		}, ENTRY_VERIFY_CB(SelectSystemCall, {
			verify_select_entry(sc, good, true);
		}), EXIT_VERIFY_CB(SelectSystemCall, {
			verify_select_exit(sc, good, true);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				int fd[2];
				if (pipe(fd) < 0) {
					return;
				}

				int readfd = fd[0];
				int writefd = fd[1];
				writefd = dup2(writefd, 1023);

				auto readset = alloc_struct32<fd_set>();
				auto writeset = alloc_struct32<fd_set>();;

				FD_SET(readfd, readset);
				FD_SET(writefd, writeset);

				auto tv = alloc_struct32<clues::timeval32>();
				tv->tv_sec = 50;
				tv->tv_usec = 100;
				auto args = alloc_struct32<
					clues::select_arg_struct>();

				args->nfds = writefd + 1;
				args->readset_p = (uintptr_t)(readset);
				args->writeset_p = (uintptr_t)(writeset);
				args->exceptset_p = 0;
				args->timeval_p = (uintptr_t)(tv);

				syscall32(SyscallNr32::SELECT, args);
			})
		}, "oldselect", {ABI::I386}
	},
#endif // SYS_select
	/* available on all ABIs, but uses 32-bit timespec on I386 */
	TestSpec{SystemCallNr::PSELECT6, []() {
			call_pselect<>();
		}, ENTRY_VERIFY_CB(PSelectSystemCall, {
			verify_pselect_entry(sc, good);
		}), EXIT_VERIFY_CB(PSelectSystemCall, {
			verify_pselect_exit(sc, good);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				call_pselect32<clues::timespec32>();
			})
		}
	},
#ifdef COSMOS_X86
	/* variant on I386 using 64-bit timespec */
	TestSpec{SystemCallNr::PSELECT6_TIME64, []() {
#ifdef COSMOS_I386
			call_pselect<clues::timespec64>(SYS_pselect6_time64);
#endif
		}, ENTRY_VERIFY_CB(PSelectSystemCall, {
			verify_pselect_entry(sc, good);
		}), EXIT_VERIFY_CB(PSelectSystemCall, {
			verify_pselect_exit(sc, good);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				call_pselect32<clues::timespec64>(SyscallNr32::PSELECT6_TIME64);
			})
		}, "", {ABI::I386}
	},
#endif
#ifndef COSMOS_AARCH64
	TestSpec{SystemCallNr::EPOLL_CREATE, []() {
			::epoll_create(128);
		}, ENTRY_VERIFY_CB(EPollCreateSystemCall, {
			VERIFY(!sc.flags);
			VERIFY(sc.size);
			VERIFY(sc.size->value() == 128);
		}), EXIT_VERIFY_CB(EPollCreateSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::EPOLL_CREATE, 128);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::EPOLL_CREATE1, []() {
			::epoll_create1(EPOLL_CLOEXEC);
		}, ENTRY_VERIFY_CB(EPollCreateSystemCall, {
			VERIFY(sc.flags);
			VERIFY(!sc.size);
			VERIFY(sc.flags->flags().raw() == EPOLL_CLOEXEC);
		}), EXIT_VERIFY_CB(EPollCreateSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::EPOLL_CREATE1, EPOLL_CLOEXEC);
			})
		}
	},
};

} // end anon ns


int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
