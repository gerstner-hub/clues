// C++
#include <sstream>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/Engine.hxx>
#include <clues/format.hxx>
#include <clues/items/fs.hxx>
#include <clues/macros.h>
#include <clues/syscalls/fs.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>
// private
#include <clues/private/kernel/dirent.hxx>
#include <clues/private/kernel/statfs.hxx>
#include <clues/private/kernel/stat.hxx>
#include <clues/private/utils.hxx>

namespace clues::item {

std::string FileDescriptor::str() const {
	if (m_at_semantics && m_fd == cosmos::FileNum::AT_CWD)
		return "AT_FDCWD";

	auto ret = std::to_string(cosmos::to_integral(m_fd));

	if (m_info) {
		ret += format::fd_info(*m_info);
	}

	return ret;
}

void FileDescriptor::processValue(const Tracee &proc) {
	m_fd = valueAs<cosmos::FileNum>();

	if (proc.engine().formatFlags()[Engine::FormatFlag::FD_INFO]) {
		m_info.reset();

		const auto &map = proc.fdInfoMap();

		if (auto it = map.find(m_fd); it != map.end()) {
			m_info = it->second;
		}
	}
}

std::string OpenFlagsValue::str() const {
	/*
	 * When compling for x86_64 then O_LARGEFILE is defined to 0, which won't work
	 * when tracing 32-bit emulation binaries. The purpose of O_LARGEFILE being
	 * defined to 0 on x86_64 is to avoid passing the bit to `open()`
	 * unnecessarily.
	 * For tracing, in the context of this compilation unit, it should be okay to
	 * redefine the value to the actual O_LARGEFILE bit to make it visible when
	 * tracing 32-bit emulation binaries.
	 * Hopefully the value is the same on other architectures as well.
	 */
#if O_LARGEFILE == 0
#	define RESTORE_LARGEFILE
#	pragma push_macro("O_LARGEFILE")
#	undef O_LARGEFILE
#	define O_LARGEFILE 0100000
#endif

	BITFLAGS_FORMAT_START_COMBINED(m_flags, valueAs<int>());

	switch (m_mode) {
		default: BITFLAGS_STREAM() << "O_???"; break;
		case cosmos::OpenMode::READ_ONLY:  BITFLAGS_STREAM() << "O_RDONLY"; break;
		case cosmos::OpenMode::WRITE_ONLY: BITFLAGS_STREAM() << "O_WRONLY"; break;
		case cosmos::OpenMode::READ_WRITE: BITFLAGS_STREAM() << "O_RDWR"; break;
	}

	BITFLAGS_STREAM() << '|';

	BITFLAGS_ADD(O_APPEND);
	BITFLAGS_ADD(O_ASYNC);
	BITFLAGS_ADD(O_CLOEXEC);
	BITFLAGS_ADD(O_CREAT);
	BITFLAGS_ADD(O_DIRECT);
	BITFLAGS_ADD(O_DIRECTORY);
	BITFLAGS_ADD(O_DSYNC);
	BITFLAGS_ADD(O_EXCL);
	BITFLAGS_ADD(O_LARGEFILE);
	BITFLAGS_ADD(O_NOATIME);
	BITFLAGS_ADD(O_NOCTTY);
	BITFLAGS_ADD(O_NOFOLLOW);
	BITFLAGS_ADD(O_NONBLOCK);
	BITFLAGS_ADD(O_PATH);
	BITFLAGS_ADD(O_SYNC);
	BITFLAGS_ADD(O_TMPFILE);
	BITFLAGS_ADD(O_TRUNC);

	return BITFLAGS_STR();
#ifdef RESTORE_LARGEFILE
#	pragma pop_macro("O_LARGEFILE")
#endif
}

void OpenFlagsValue::processValue(const Tracee &) {
	const auto raw = valueAs<int>();
	// the access mode consists of the lower two bits
	m_mode = cosmos::OpenMode{raw & 0x3};
	m_flags = cosmos::OpenFlags{raw & ~0x3};
}

std::string AtFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(AT_EMPTY_PATH);
	BITFLAGS_ADD(AT_SYMLINK_NOFOLLOW);
	BITFLAGS_ADD(AT_SYMLINK_FOLLOW);
	/*
	 * some AT_ constants share the same values and are system call
	 * dependent, thus we need to check the context here.
	 */
	if (m_call->callNr() == SystemCallNr::UNLINKAT)
		BITFLAGS_ADD(AT_REMOVEDIR);
	if (m_call->callNr() == SystemCallNr::FACCESSAT2)
		BITFLAGS_ADD(AT_EACCESS);
	if (m_call->callNr() == SystemCallNr::FSTATAT64 || m_call->callNr() == SystemCallNr::NEWFSTATAT)
		BITFLAGS_ADD(AT_NO_AUTOMOUNT);

	return BITFLAGS_STR();
}

void AtFlagsValue::processValue(const Tracee&) {
	m_flags = AtFlags{valueAs<int>()};
}

void AccessModeParameter::processValue(const Tracee&) {
	m_checks = cosmos::fs::AccessChecks(valueAs<int>());
}

std::string AccessModeParameter::str() const {
	using cosmos::fs::AccessCheck;

	std::string ret;

	if (m_checks.none()) {
		ret = "F_OK";
	} else {
		if (m_checks[AccessCheck::READ_OK]) {
			ret += "R_OK|";
		}
		if (m_checks[AccessCheck::WRITE_OK]) {
			ret += "W_OK|";
		}
		if (m_checks[AccessCheck::EXEC_OK]) {
			ret += "X_OK";
		}
	}

	if (ret.empty()) {
		return "???";
	}

	return strip_back(std::move(ret));
}

std::string FileModeParameter::str() const {
	return format::file_mode_numeric(m_mode.mask()) +
		" (" + m_mode.symbolic() + ")";
}

std::string StatParameter::str() const {
	if (!m_stat) {
		if (isZero()) {
			return "NULL";
		} else {
			return "<invalid>";
		}
	}

	const auto st = *m_stat->raw();
	using namespace std::string_literals;

	const auto is_old_stat = isOldStat();

	std::string ret = std::format("{{ino={}, dev={}, mode={}|{}, nlink={}, uid={}, gid={}, ",
		st.st_ino, format::device_id(m_stat->device()), format::file_type(m_stat->type()),
		format::file_mode_numeric(m_stat->mode().mask()), m_stat->numLinks(),
		m_stat->uid(), m_stat->gid());

	if (m_stat->type().isCharDev() || m_stat->type().isBlockDev()) {
		ret += std::format("rdev={}, ", format::device_id(m_stat->representedDevice()));
	}

	ret += std::format("size={}, ", st.st_size);

	if (!is_old_stat) {
		/*
		 * these fields do not exist in oldstat syscalls
		 */
		ret += std::format("blksize={}, blocks={}, ",
				m_stat->blockSize(), m_stat->allocatedBlocks());
	}

	ret += std::format("atim={}, mtim={}, ctim={}}}",
		format::timespec(m_stat->accessTime(), is_old_stat),
		format::timespec(m_stat->modTime(), is_old_stat),
		format::timespec(m_stat->statusTime(), is_old_stat));

	return ret;
}

bool StatParameter::isOldStat() const {
	using enum SystemCallNr;

	switch (m_call->callNr()) {
		case OLDSTAT: [[fallthrough]];
		case OLDLSTAT: [[fallthrough]];
		case OLDFSTAT: return true;
		default: return false;
	}
}

bool StatParameter::isStat64() const {
	using enum SystemCallNr;

	switch (m_call->callNr()) {
		case STAT64: [[fallthrough]];
		case LSTAT64: [[fallthrough]];
		case FSTAT64: [[fallthrough]];
		case FSTATAT64: return true;
		default: return false;
	}
}

bool StatParameter::isRegularStat() const {
	using enum SystemCallNr;

	switch (m_call->callNr()) {
		case SystemCallNr::STAT: [[fallthrough]];
		case SystemCallNr::LSTAT: [[fallthrough]];
		case SystemCallNr::FSTAT: return true;
		default: return false;
	}
}

void StatParameter::updateData(const Tracee &proc) {
	if (!m_stat) {
		m_stat.emplace();
	}

#if defined(COSMOS_X86_64) || defined(COSMOS_AARCH64)
	/*
	 * on 64-bit platforms life is simple, we directly copy the data into
	 * a cosmos::FileStatus struct.
	 * make sure the raw kernel data structure `stat64` matches `struct
	 * stat` and then copy everything into it.
	 */
	static_assert(sizeof(*m_stat->raw()) == sizeof(stat64));
#else
	/* on I386 with TIME_BITS=64 the `struct stat` exposed by glibc does
	 * not match the kernel structure, because it now contains 64-bit
	 * time_t, but on the kernel side only statx supports 64-bit times on
	 * 32-bit ABIs */
#endif

	auto fetch_and_copy = [this, &proc]<typename STAT>() {
		STAT st;
		if (!proc.readStruct(asPtr(), st)) {
			m_stat.reset();
			return;
		}

		auto &raw = *m_stat->raw();
		/*
		 * to be layout-agnostic simply copy over field-by-field
		 */
		raw.st_dev = st.dev;
		raw.st_ino = st.ino;
		raw.st_mode = st.mode;
		raw.st_nlink = st.nlink;
		raw.st_uid = st.uid;
		raw.st_gid = st.gid;
		raw.st_rdev = st.rdev;
		raw.st_size = st.size;

		if constexpr (std::is_same_v<STAT, old_kernel_stat>) {
			/* the old kernel stat is missing a lot of stuff */
			raw.st_atim.tv_sec = st.atime;
			raw.st_atim.tv_nsec = 0;
			raw.st_mtim.tv_sec = st.mtime;
			raw.st_mtim.tv_nsec = 0;
			raw.st_ctim.tv_sec = st.ctime;
			raw.st_ctim.tv_nsec = 0;
			raw.st_blksize = 0;
			raw.st_blocks = 0;
		}

		if constexpr (!std::is_same_v<STAT, old_kernel_stat>) {
			raw.st_blksize = st.blksize;
			raw.st_blocks = st.blocks;
			raw.st_atim.tv_sec = st.atime;
			raw.st_atim.tv_nsec = st.atime_nsec;
			raw.st_mtim.tv_sec = st.mtime;
			raw.st_mtim.tv_nsec = st.mtime_nsec;
			raw.st_ctim.tv_sec = st.ctime;
			raw.st_ctim.tv_nsec = st.ctime_nsec;
		}
	};

	switch (m_call->abi()) {
		case ABI::X86_64: [[fallthrough]];
		case ABI::X32:    [[fallthrough]];
		case ABI::AARCH64: {
			/*
			 * there's only one type of stat
			 * directly read into libcosmos's FileStatus
			 */
			if (!proc.readStruct(asPtr(), *m_stat->raw())) {
				m_stat.reset();
			}
			break;
		} case ABI::I386: {
			/*
			 * on 32-bit platforms things get messy, we have three
			 * different possibilities using three different data
			 * structures.
			 */
			if (isOldStat()) {
				fetch_and_copy.operator()<old_kernel_stat>();
			} else if (isStat64()) {
				fetch_and_copy.operator()<stat32_64>();
			} else if (isRegularStat()) {
				// regular 32-bit stat
				fetch_and_copy.operator()<stat32>();
			} else {
				throw cosmos::RuntimeError{"unexpected syscall nr for struct stat"};
			}
			break;
		} default: throw cosmos::RuntimeError{"unexpected ABI for struct stat"};
	}
}

static std::string_view entry_type_label(const cosmos::DirEntry::Type type) {
	switch (cosmos::to_integral(type)) {
		CASE_ENUM_TO_STR(DT_BLK);
		CASE_ENUM_TO_STR(DT_CHR);
		CASE_ENUM_TO_STR(DT_DIR);
		CASE_ENUM_TO_STR(DT_FIFO);
		CASE_ENUM_TO_STR(DT_LNK);
		CASE_ENUM_TO_STR(DT_REG);
		CASE_ENUM_TO_STR(DT_SOCK);
		CASE_ENUM_TO_STR(DT_UNKNOWN);
		default: return "???";
	}
}

std::string DirEntries::str() const {
	auto result = m_call->result();

	if (!result) {
		return "undefined";
	} else if (m_entries.empty()) {
		return "empty";
	} else {
		std::string ret = std::format("{} entries: ", m_entries.size());

		std::string comma;

		for (const auto &entry: m_entries) {
			ret += comma;
			ret += std::format("{{d_ino={}, d_off={}, d_reclen={}, d_name=\"{}\", d_type={}}}",
				entry.inode, entry.offset,
				offsetof(struct linux_dirent, d_name) + entry.name.length() + 2,
				entry.name,
				entry_type_label(entry.type));

			if (comma.empty()) {
				comma = ", ";
			}
		}

		return ret;
	}
}

void DirEntries::updateData(const Tracee &proc) {
	// the amount of data stored at the DirEntries location depends on the
	// system call result value.
	auto result = m_call->result();
	if (!result)
		// error occurred
		return;

	const auto bytes = result->valueAs<size_t>();
	if (bytes == 0)
		// empty
		return;

	/*
	 * first copy over all the necessary data from the tracee
	 */
	m_buffer = std::unique_ptr<char[]>(new char[bytes]);
	proc.readBlob(asPtr(), m_buffer.get(), bytes);

	if (m_call->callNr() == SystemCallNr::GETDENTS64) {
		parseEntries64(bytes);
	} else {
		if (m_call->is32BitEmulationABI()) {
			parseEntries32<struct linux_dirent32>(bytes);
		} else {
			parseEntries32<struct linux_dirent>(bytes);
		}
	}
}

template <typename DIRENT>
void DirEntries::parseEntries32(const size_t bytes) {

	DIRENT *cur = nullptr;
	size_t pos = 0;
	constexpr auto NAME_OFFSET = offsetof(DIRENT, d_name);

	while (pos < bytes) {
		cur = (DIRENT*)(m_buffer.get() + pos);
		auto namelen = cur->d_reclen - NAME_OFFSET - 2;
		/*
		 * the length can still include padding, thus look from the
		 * back for the first non-zero byte at the end to correct the
		 * length.
		 */
		for (char *last = cur->d_name + namelen - 1; last > cur->d_name && *last == '\0'; last--, namelen--);

		const auto type = *(m_buffer.get() + pos + cur->d_reclen - 1);

		m_entries.emplace_back(Entry{
			cur->d_ino,
			static_cast<int64_t>(cur->d_off),
			// to avoid copying we only keep a string_view in
			// Entry pointing to the raw buffer data.
			std::string_view{cur->d_name, namelen},
			cosmos::DirEntry::Type{static_cast<unsigned char>(type)}
		});
		pos += cur->d_reclen;
	}
}

void DirEntries::parseEntries64(const size_t bytes) {
	struct linux_dirent64 *cur = nullptr;
	size_t pos = 0;
	constexpr auto NAME_OFFSET = offsetof(linux_dirent64, d_name);

	while (pos < bytes) {
		cur = (linux_dirent64*)(m_buffer.get() + pos);
		auto namelen = cur->d_reclen - NAME_OFFSET;
		/*
		 * remove padding from length
		 */
		for (char *last = cur->d_name + namelen - 1; last > cur->d_name && *last == '\0'; last--, namelen--);

		m_entries.emplace_back(Entry{
			cur->d_ino,
			cur->d_off,
			std::string_view{cur->d_name, namelen},
			cosmos::DirEntry::Type{static_cast<unsigned char>(cur->d_type)}
		});

		pos += cur->d_reclen;
	}
}

void AccessAdvice::processValue(const Tracee &) {
	m_advice = cosmos::FileDescriptor::AccessAdvice{valueAs<int>()};
}

std::string AccessAdvice::str() const {
	switch (cosmos::to_integral(m_advice)) {
		CASE_ENUM_TO_STR(POSIX_FADV_NORMAL);
		CASE_ENUM_TO_STR(POSIX_FADV_SEQUENTIAL);
		CASE_ENUM_TO_STR(POSIX_FADV_RANDOM);
		CASE_ENUM_TO_STR(POSIX_FADV_NOREUSE);
		CASE_ENUM_TO_STR(POSIX_FADV_WILLNEED);
		CASE_ENUM_TO_STR(POSIX_FADV_DONTNEED);
		default: return "POSIX_FADV_???";
	}
}

namespace {

std::string_view fstype2str(const cosmos::FileSystemStatus::Magic magic) {
	/* there is no complete list of C literals for these constants, so use
	 * the abbreviated libcosmos ones */
	using enum cosmos::FileSystemStatus::Magic;

	switch (magic) {
		CASE_ENUM_TO_STR(ADFS);
		CASE_ENUM_TO_STR(AFFS);
		CASE_ENUM_TO_STR(AFS);
		CASE_ENUM_TO_STR(ANON_INODE_FS);
		CASE_ENUM_TO_STR(AUTOFS);
		CASE_ENUM_TO_STR(BDEVFS);
		CASE_ENUM_TO_STR(BEFS);
		CASE_ENUM_TO_STR(BFS);
		CASE_ENUM_TO_STR(BINFMTFS);
		CASE_ENUM_TO_STR(BPF_FS);
		CASE_ENUM_TO_STR(BTRFS);
		CASE_ENUM_TO_STR(BTRFS_TEST);
		CASE_ENUM_TO_STR(CGROUP);
		CASE_ENUM_TO_STR(CGROUP2);
		CASE_ENUM_TO_STR(CIFS);
		CASE_ENUM_TO_STR(CODA);
		CASE_ENUM_TO_STR(COH);
		CASE_ENUM_TO_STR(CRAMFS);
		CASE_ENUM_TO_STR(DEBUGFS);
		CASE_ENUM_TO_STR(DEVFS);
		CASE_ENUM_TO_STR(DEVPTS);
		CASE_ENUM_TO_STR(ECRYPTFS);
		CASE_ENUM_TO_STR(EFIVARFS);
		CASE_ENUM_TO_STR(EFS);
		CASE_ENUM_TO_STR(EXT);
		CASE_ENUM_TO_STR(EXT2_OLD);
		CASE_ENUM_TO_STR(EXT2_3_4);
		CASE_ENUM_TO_STR(F2FS);
		CASE_ENUM_TO_STR(FUSE);
		CASE_ENUM_TO_STR(FUTEXFS);
		CASE_ENUM_TO_STR(HFS);
		CASE_ENUM_TO_STR(HOSTFS);
		CASE_ENUM_TO_STR(HPFS);
		CASE_ENUM_TO_STR(HUGETLBFS);
		CASE_ENUM_TO_STR(ISOFS);
		CASE_ENUM_TO_STR(JFFS2);
		CASE_ENUM_TO_STR(JFS);
		CASE_ENUM_TO_STR(MINIX);
		CASE_ENUM_TO_STR(MINIX_2);
		CASE_ENUM_TO_STR(MINIX2);
		CASE_ENUM_TO_STR(MINIX2_2);
		CASE_ENUM_TO_STR(MINIX3);
		CASE_ENUM_TO_STR(MQUEUE);
		CASE_ENUM_TO_STR(MSDOS);
		CASE_ENUM_TO_STR(MTD_INODE_FS);
		CASE_ENUM_TO_STR(NCP);
		CASE_ENUM_TO_STR(NFS);
		CASE_ENUM_TO_STR(NILFS);
		CASE_ENUM_TO_STR(NSFS);
		CASE_ENUM_TO_STR(NTFS_SB);
		CASE_ENUM_TO_STR(OCFS2);
		CASE_ENUM_TO_STR(OPENPROM);
		CASE_ENUM_TO_STR(OVERLAYFS);
		CASE_ENUM_TO_STR(PIPEFS);
		CASE_ENUM_TO_STR(PROC);
		CASE_ENUM_TO_STR(PSTOREFS);
		CASE_ENUM_TO_STR(QNX4);
		CASE_ENUM_TO_STR(QNX6);
		CASE_ENUM_TO_STR(RAMFS);
		CASE_ENUM_TO_STR(REISERFS);
		CASE_ENUM_TO_STR(ROMFS);
		CASE_ENUM_TO_STR(SECURITYFS);
		CASE_ENUM_TO_STR(SELINUX);
		CASE_ENUM_TO_STR(SMACK);
		CASE_ENUM_TO_STR(SMB);
		CASE_ENUM_TO_STR(SMB2);
		CASE_ENUM_TO_STR(SOCKFS);
		CASE_ENUM_TO_STR(SQUASHFS);
		CASE_ENUM_TO_STR(SYSFS);
		CASE_ENUM_TO_STR(SYSV2);
		CASE_ENUM_TO_STR(SYSV4);
		CASE_ENUM_TO_STR(TMPFS);
		CASE_ENUM_TO_STR(TRACEFS);
		CASE_ENUM_TO_STR(UDF);
		CASE_ENUM_TO_STR(UFS);
		CASE_ENUM_TO_STR(USBDEVICE);
		CASE_ENUM_TO_STR(V9FS);
		CASE_ENUM_TO_STR(VXFS);
		CASE_ENUM_TO_STR(XENFS);
		CASE_ENUM_TO_STR(XENIX);
		CASE_ENUM_TO_STR(XFS);
		CASE_ENUM_TO_STR(XIAFS);
		default: return "???_MAGIC";
	}
}

std::string mount_opts2str(const cosmos::FileSystemStatus::MountOptions opts) {
	BITFLAGS_FORMAT_START(opts);

	BITFLAGS_ADD(ST_MANDLOCK);
	BITFLAGS_ADD(ST_NOATIME);
	BITFLAGS_ADD(ST_NODEV);
	BITFLAGS_ADD(ST_NODIRATIME);
	BITFLAGS_ADD(ST_NOEXEC);
	BITFLAGS_ADD(ST_NOSUID);
	BITFLAGS_ADD(ST_RDONLY);
	BITFLAGS_ADD(ST_RELATIME);
	BITFLAGS_ADD(ST_SYNCHRONOUS);
	BITFLAGS_ADD(ST_NOSYMFOLLOW);

	return BITFLAGS_STR();
}

} // end anon ns

std::string StatFSParameter::str() const {
	if (!m_stat) {
		return PointerValue::formatBadPointer();
	}

	const auto &st = *m_stat;

	return std::format("{{f_type={}, f_bsize={}, f_blocks={}, f_bfree={}, "
			"f_bavail={}, f_files={}, f_ffree={}, f_fsid={}:{}, "
			"f_namelen={}, f_frsize={}, f_flags={}}}",
		fstype2str(st.fsType()), st.blockSize(), st.totalBlocks(),
		st.freeBlocks(), st.availableBlocks(), st.totalInodes(),
		st.freeInodes(), st.id().__val[0], st.id().__val[1], st.nameLen(),
		st.fragmentSize(), mount_opts2str(st.options())
	);
}

bool StatFSParameter::isStatFS64() const {
	switch (m_call->callNr()) {
		case SystemCallNr::FSTATFS64: /* fallthrough */
		case SystemCallNr::STATFS64: return true;
		default: return false;
	}
}

bool StatFSParameter::isRegularStatFS() const {
	switch (m_call->callNr()) {
		case SystemCallNr::FSTATFS: /* fallthrough */
		case SystemCallNr::STATFS: return true;
		default: return false;
	}
}

void StatFSParameter::updateData(const Tracee &proc) {
#if defined(COSMOS_X86_64) || defined(COSMOS_AARCH64)
	static_assert(sizeof(*m_stat->raw()) == sizeof(clues::statfs));
#else
	/*
	 * on modern 32-bit we can still do the same for the stat64 family of
	 * system calls, but only if the tracer is 32-bit as well...
	 */
	static_assert(sizeof(*m_stat->raw()) == sizeof(clues::statfs64));
#endif
	m_stat.emplace();

#ifdef COSMOS_X86
	auto fetch_and_copy = [this, &proc]<typename STATFS>() {
		STATFS st;
		if (!proc.readStruct(asPtr(), st)) {
			m_stat.reset();
			return;
		}

		auto &raw = *m_stat->raw();
		/*
		 * to be layout-agnostic simply copy over field-by-field
		 */
		raw.f_type = st.f_type;
		raw.f_bsize = st.f_bsize;
		raw.f_blocks = st.f_blocks;
		raw.f_bfree = st.f_bfree;
		raw.f_bavail = st.f_bavail;
		raw.f_files = st.f_files;
		raw.f_ffree = st.f_ffree;
		static_assert(sizeof(raw.f_fsid) == sizeof(st.f_fsid), "fsid size mismatch");
		std::memcpy(&raw.f_fsid, &st.f_fsid, sizeof(raw.f_fsid));
		raw.f_namelen = st.f_namelen;
		raw.f_frsize = st.f_frsize;
		raw.f_flags = st.f_flags;
	};
#endif

	switch (m_call->abi()) {
		case ABI::X86_64: [[fallthrough]];
		case ABI::X32:    [[fallthrough]];
		case ABI::AARCH64: {
			/*
			 * there's only one type of stat
			 * directly read into libcosmos's FileSystemStatus
			 */
			if (!proc.readStruct(asPtr(), *m_stat->raw())) {
				m_stat.reset();
			}
			break;
		} case ABI::I386: {
#ifdef COSMOS_X86
			/*
			 * we have regular statfs using 32-bit fields and
			 * statfs64 using some 64-bit fields. for cross ABI
			 * tracing the private header already exposes a
			 * properly aligned structure for us to work on.
			 */
			if (isStatFS64()) {
				if (m_call->is32BitEmulationABI()) {
					fetch_and_copy.operator()<clues::statfs64>();
				} else {
					if (!proc.readStruct(asPtr(), *m_stat->raw())) {
						m_stat.reset();
					}
				}
			} else if (isRegularStatFS()) {
				if (m_call->is32BitEmulationABI()) {
#	ifdef COSMOS_X86_64
					fetch_and_copy.operator()<clues::statfs32>();
#	endif
				} else {
					fetch_and_copy.operator()<clues::statfs>();
				}
			} else {
				throw cosmos::RuntimeError{"unexpected syscall nr for struct statfs"};
			}
#endif
			break;
		} default: throw cosmos::RuntimeError{"unexpected ABI for struct statfs"};
	}
}

} // end ns
