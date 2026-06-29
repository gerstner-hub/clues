// test
#include "utils/syscalls.hxx"

// Linux
#include <fcntl.h>
#include <unistd.h>

namespace {

/* check routines shared between multiple system calls */

/* shared entry check for faccessat1/2 */
template <typename SC>
void check_faccessat_entry(const SC &access_sc, bool &good) {
	VERIFY(access_sc.dirfd.fd() == FIRST_FD);
	VERIFY(access_sc.path.data() == "etc");

	using cosmos::fs::AccessCheck;
	using cosmos::fs::AccessChecks;
	const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
	VERIFY(access_sc.mode.checks() == checks);
};

const auto TESTS = std::array{
#ifdef CLUES_HAVE_ACCESS
	TestSpec{SystemCallNr::ACCESS, []() {
			access("/etc/", R_OK|X_OK);
		}, ENTRY_VERIFY_CB(AccessSystemCall, {
			VERIFY(sc.path.data() == "/etc/");
			using cosmos::fs::AccessCheck;
			using cosmos::fs::AccessChecks;
			const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
			VERIFY(sc.mode.checks() == checks);
		}), EXIT_VERIFY_CB(AccessSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				syscall32(SyscallNr32::ACCESS,
					alloc_str32("/etc/"), R_OK|X_OK);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::FACCESSAT, []() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat, dirfd, "etc", R_OK|X_OK);
		}, ENTRY_VERIFY_CB(FAccessAtSystemCall, {
			check_faccessat_entry(sc, good);
		}), EXIT_VERIFY_CB(FAccessAtSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::FACCESSAT, dirfd, alloc_str32("etc"), R_OK|X_OK);
			})
		}
	}, TestSpec{SystemCallNr::FACCESSAT2, []() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat2, dirfd, "etc", R_OK|X_OK, AT_EACCESS);
		}, ENTRY_VERIFY_CB(FAccessAt2SystemCall, {
			check_faccessat_entry(sc, good);
			if (!good)
				return;
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(sc.flags.flags() == AtFlags{EACCESS})
		}), EXIT_VERIFY_CB(FAccessAt2SystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
					auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
					syscall32(SyscallNr32::FACCESSAT2, dirfd, alloc_str32("etc"), R_OK|X_OK, AT_EACCESS);
			})
		}
	   /* TODO: cover more operations from fcntl */
	}, TestSpec{SystemCallNr::FCNTL, []() { /* F_GETFD test */
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			syscall(SYS_fcntl, fd, F_GETFD);
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::GETFD);
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			VERIFY(sc.hasResultValue());
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.ret_fd_flags->flags() == DescFlags{CLOEXEC});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL, fd, F_GETFD);
			})
		},
		"GETFD"
	}, TestSpec{SystemCallNr::FCNTL, []() { /* F_SETFD test */
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::SETFD);
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.fd_flags_arg->flags() == DescFlags{CLOEXEC});
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL, fd, F_SETFD, FD_CLOEXEC);
			})
		},
		"SETFD"
	}, TestSpec{SystemCallNr::FCNTL64, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			syscall(SYS_fcntl64, fd, F_GETFD);
#endif
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::GETFD);
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ret_fd_flags->flags() == DescFlags{CLOEXEC});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL64, fd, F_GETFD);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::FSTAT, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			struct stat st;
			syscall(SYS_fstat, fd, &st);
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				/* the size of this struct stat is too big,
				 * but it doesn't matter as long as we don't
				 * interpret it in this callback */
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::FSTAT, fd, st);
			})
		},
	}, TestSpec{SystemCallNr::FSTAT64, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			struct stat st;
			syscall(SYS_fstat64, fd, &st);
#endif
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::FSTAT64, fd, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::OLDFSTAT, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			/* the struct will be too big, bug that should be no
			 * matter as long as we don't touch it here */
			struct stat st;
			TWICE(syscall(SYS_oldfstat, fd, &st));
#endif
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			/* NOTE: this call could fail if some of the metadata
			 * doesn't fit in the old stat structure */
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::OLDFSTAT, fd, st);
			})
		},
		"",
		{clues::ABI::I386}
#ifdef CLUES_HAVE_LEGACY_GETDENTS
	}, TestSpec{SystemCallNr::GETDENTS, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			char buffer[65535];
			/* do it TWICE, but we need to seek back to the
			 * beginning of the directory here, thus it needs
			 * extra code */
			syscall(SYS_getdents, fd, buffer, sizeof(buffer));
			lseek(fd, 0, SEEK_SET);
			syscall(SYS_getdents, fd, buffer, sizeof(buffer));
		}, ENTRY_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.dirent.entries().size() == 0);
			VERIFY(sc.size.value() == 65535);
		}), EXIT_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto bytes = sc.ret_bytes.value();
			VERIFY(bytes > 0 && bytes < 65535);
			const auto &entries = sc.dirent.entries();
			// a least ".", ".."
			VERIFY(entries.size() > 2);
			bool found_tmp = false;
			bool found_root = false;

			using enum cosmos::DirEntry::Type;

			for (const auto &entry: entries) {
				if (entry.name == "tmp") {
					found_tmp = true;
					VERIFY(entry.type == DIRECTORY);
				} else if (entry.name == "root") {
					found_root = true;
					VERIFY(entry.type == DIRECTORY);
				}
			}

			VERIFY(found_tmp && found_root);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				char *buffer = alloc32<char*>(65535);
				syscall32(SyscallNr32::GETDENTS, fd, buffer, 65535);
			})
		}
#endif
	}, TestSpec{SystemCallNr::GETDENTS64, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			char buffer[65535];
			syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
		}, ENTRY_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.size.value() == 65535);
		}), EXIT_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto bytes = sc.ret_bytes.valueAs<unsigned int>();
			VERIFY(bytes > 0 && bytes < 65535);
			const auto &entries = sc.dirent.entries();
			// a least ".", ".."
			VERIFY(entries.size() > 2);
			bool found_tmp = false;
			bool found_root = false;

			using enum cosmos::DirEntry::Type;

			for (const auto &entry: entries) {
				if (entry.name == "tmp") {
					found_tmp = true;
					VERIFY(entry.type == DIRECTORY);
				} else if (entry.name == "root") {
					found_root = true;
					VERIFY(entry.type == DIRECTORY);
				}
			}

			VERIFY(found_tmp && found_root);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				char *buffer = alloc32<char*>(65535);
				syscall32(SyscallNr32::GETDENTS64, fd, buffer, 65535);
			})
		}
#ifdef CLUES_HAVE_LSTAT
	}, TestSpec{SystemCallNr::LSTAT, []() {
			struct stat st;
			TWICE(syscall(SYS_lstat, "/", &st));
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				/* struct will be too big, but that doesn't
				 * matter for testing */
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::LSTAT, path, st);
			})
		}
#endif
	}, TestSpec{SystemCallNr::LSTAT64, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_lstat64, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::LSTAT64, path, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::OLDLSTAT, []() {
#ifdef COSMOS_I386
			/* the struct will be too big, bug that should be no
			 * matter as long as we don't touch it here */
			struct stat st;
			TWICE(syscall(SYS_oldlstat, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::OLDLSTAT, path, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::STAT64, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_stat64, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::STAT64, path, st);
			})
		},
		"",
		{clues::ABI::I386}
#ifdef CLUES_HAVE_STAT
	}, TestSpec{SystemCallNr::STAT, []() {
			struct stat st;
			TWICE(syscall(SYS_stat, "/", &st));
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::STAT, path, st);
			})
		}
#endif
	}, TestSpec{SystemCallNr::OLDSTAT, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_oldstat, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::OLDSTAT, path, st);
			})
		},
		"",
		{clues::ABI::I386}
#ifdef CLUES_HAVE_OPEN
	}, TestSpec{SystemCallNr::OPEN, []() {
			syscall(SYS_open, "/etc/fstab", O_RDONLY|O_CLOEXEC);
		}, ENTRY_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.filename.data() == "/etc/fstab");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC});
			VERIFY(sc.flags.mode() == READ_ONLY);
			VERIFY(!sc.mode.has_value());
		}), EXIT_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto path = alloc_str32("/etc/fstab");
				syscall32(SyscallNr32::OPEN, path, O_RDONLY|O_CLOEXEC);
			})
		}
	}, TestSpec{SystemCallNr::OPEN, []() {
			syscall(SYS_open, "/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
		}, ENTRY_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.filename.data() == "/tmp");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC,TMPFILE});
			VERIFY(sc.flags.mode() == WRITE_ONLY);
			VERIFY(sc.mode.has_value());
			const auto &mode_par = *sc.mode;
			VERIFY(mode_par.mode() == cosmos::FileMode{cosmos::FileModeBit{0755}});
		}), EXIT_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto path = alloc_str32("/tmp");
				syscall32(SyscallNr32::OPEN, path, O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
			})
		},
		"CREAT"
#endif
	}, TestSpec{SystemCallNr::OPENAT, []() {
			auto fd = open("/etc", O_RDONLY|O_DIRECTORY);
			syscall(SYS_openat, fd, "fstab", O_RDONLY|O_CLOEXEC);
		}, ENTRY_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD)
			VERIFY(sc.filename.data() == "fstab");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC});
			VERIFY(sc.flags.mode() == READ_ONLY);
			VERIFY(!sc.mode.has_value());
		}), EXIT_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == SECOND_FD);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto dirpath = alloc_str32("/etc");
				auto filepath = alloc_str32("fstab");
				auto fd = open(dirpath, O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::OPENAT, fd, filepath, O_RDONLY|O_CLOEXEC);
			})
		},
	}, TestSpec{SystemCallNr::OPENAT, []() {
			auto fd = open("/tmp", O_RDONLY|O_DIRECTORY);
			syscall(SYS_openat, fd, ".", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
		}, ENTRY_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD)
			VERIFY(sc.filename.data() == ".");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC,TMPFILE});
			VERIFY(sc.flags.mode() == WRITE_ONLY);
			VERIFY(sc.mode.has_value());
			const auto &mode_par = *sc.mode;
			VERIFY(mode_par.mode() == cosmos::FileMode{cosmos::FileModeBit{0755}});
		}), EXIT_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == SECOND_FD);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto dirpath = alloc_str32("/tmp");
				auto filepath = alloc_str32(".");
				auto fd = open(dirpath, O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::OPENAT, fd, filepath, O_WRONLY|O_CLOEXEC|O_TMPFILE, 0755);
			})
		},
		"CREAT"
	}, TestSpec{SystemCallNr::FADVISE64, []() {
		auto fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0640);
#ifdef COSMOS_X86_64
		syscall(SYS_fadvise64, fd, (1LL << 32) + 123, 4096, POSIX_FADV_NOREUSE);
#elif defined(COSMOS_I386)
		syscall(SYS_fadvise64, fd, 123, 1, 4096, POSIX_FADV_NOREUSE);
#elif defined(COSMOS_AARCH64)
		syscall(SYS_fadvise64, fd, (1LL << 32) + 123, 4096, POSIX_FADV_NOREUSE);
#else
#	error "unsupported ABI"
#endif
		}, ENTRY_VERIFY_CB(FAdviseSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset() == (1LL << 32) + 123);
			VERIFY(sc.size() == 4096);
			VERIFY(sc.advice.advice() == cosmos::FileDescriptor::AccessAdvice::NOREUSE);
		}), EXIT_VERIFY_CB(FAdviseSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0640);
				syscall32(SyscallNr32::FADVISE64, fd, 123, 1, 4096, POSIX_FADV_NOREUSE);
			})
		},
	}, TestSpec{SystemCallNr::FADVISE64_64, []() {
#ifdef COSMOS_I386
			auto fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0640);
			syscall(SYS_fadvise64_64, fd, 128, 1, 64, 2, POSIX_FADV_RANDOM);
#endif
		}, ENTRY_VERIFY_CB(FAdviseSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset() == (1LL << 32) + 128);
			VERIFY(sc.size() == (1LL << 33) + 64);
			VERIFY(sc.advice.advice() == cosmos::FileDescriptor::AccessAdvice::RANDOM);
		}), EXIT_VERIFY_CB(FAdviseSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0640);
				syscall32(SyscallNr32::FADVISE64_64, fd, 128, 1, 64, 2, POSIX_FADV_RANDOM);
			})
		}, "", {clues::ABI::I386}
	}, TestSpec{SystemCallNr::UMASK, []() {
			umask(0011);
			umask(0077);
		}, ENTRY_VERIFY_CB(UmaskSystemCall, {
			VERIFY(sc.new_mask.mode() == cosmos::FileMode{cosmos::ModeT{0077}});
		}), EXIT_VERIFY_CB(UmaskSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.old_mask.mode() == cosmos::FileMode{cosmos::ModeT{0011}});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				umask(0011);
				syscall32(SyscallNr32::UMASK, 0077);
			})
		}
	}
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
