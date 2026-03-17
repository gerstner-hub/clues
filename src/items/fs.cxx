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
#include <clues/private/kernel/stat.hxx>
#include <clues/private/kernel/dirent.hxx>
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

	if (!m_checks) {
		return "<invalid>";
	}

	const auto checks = *m_checks;

	std::stringstream ss;

	if (checks.none()) {
		ss << "F_OK";
	} else {
		if (checks[AccessCheck::READ_OK]) {
			ss << "R_OK|";
		}
		if (checks[AccessCheck::WRITE_OK]) {
			ss << "W_OK|";
		}
		if (checks[AccessCheck::EXEC_OK]) {
			ss << "X_OK";
		}
	}

	auto ret = ss.str();

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
		return "NULL";
	}

	std::stringstream ss;

	const auto st = *m_stat->raw();
	using namespace std::string_literals;

	const auto is_old_stat = isOldStat();

	ss
		<< "{"
		<< "size=" << st.st_size << ", "
		<< "ino=" << st.st_ino << ", "
		<< "dev=" << format::device_id(m_stat->device()) << ", "
		<< "mode=" << format::file_type(m_stat->type()) << "|" << format::file_mode_numeric(m_stat->mode().mask()) << ", "
		<< "nlink=" << m_stat->numLinks() << ", "
		<< "uid=" << st.st_uid << ", "
		<< "gid=" << st.st_gid << ", "
		<< (m_stat->type().isCharDev() || m_stat->type().isBlockDev() ? "rdev="s + format::device_id(m_stat->representedDevice()) + ", " : "")
		<< "size=" << st.st_size << ", ";

	if (!is_old_stat) {
		/*
		 * these fields do not exist in oldstat syscalls
		 */
		ss << "blksize=" << st.st_blksize << ", " << "blocks=" << st.st_blocks << ", ";
	}

	ss
		<< "atim=" << format::timespec(m_stat->accessTime(), is_old_stat) << ", "
		<< "mtim=" << format::timespec(m_stat->modTime(), is_old_stat) << ", "
		<< "ctim=" << format::timespec(m_stat->statusTime(), is_old_stat)
		<< "}";

	return ss.str();
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
		m_stat = std::make_optional<cosmos::FileStatus>();
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
	/*
	 * on modern 32-bit we can still do the same for the stat64 family of
	 * system calls, but only if the tracer is 32-bit as well...
	 */
	static_assert(sizeof(*m_stat->raw()) == sizeof(stat32_64));
#endif

	auto fetch_and_copy = [this, &proc]<typename STAT>() {
		STAT st;
		if (!proc.readStruct(m_val, st)) {
			m_stat.reset();
			return;
		}

		auto &raw = *m_stat->raw();
		/*
		 * to be layout agnostic simply copy over field-by-field
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
			if (!proc.readStruct(m_val, *m_stat->raw())) {
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
	std::stringstream ss;
	auto result = m_call->result();

	if (!result) {
		ss << "undefined";
	} else if (m_entries.empty()) {
		ss << "empty";
	} else {
		ss << m_entries.size() << " entries: ";

		std::string comma;

		for (const auto &entry: m_entries) {
			ss << comma << "{d_ino=" << entry.inode
				<< ", d_off=" << entry.offset
				<< ", d_reclen=" << offsetof(struct linux_dirent, d_name) + entry.name.length() + 2
				<< ", d_name=\"" << entry.name
				<< "\", d_type=" << entry_type_label(entry.type)
				<< "}";

			if (comma.empty()) {
				comma = ", ";
			}
		}
	}

	return ss.str();
}

void DirEntries::updateData(const Tracee &proc) {
	m_entries.clear();
	m_buffer.reset();

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

	if (m_call->is32BitEmulationABI()) {
		fetchEntries<struct linux_dirent32>(proc, bytes);
	} else {
		fetchEntries<struct linux_dirent>(proc, bytes);
	}
}

template <typename DIRENT>
void DirEntries::fetchEntries(const Tracee &proc, const size_t bytes) {

	/*
	 * first copy over all the necessary data from the tracee
	 */
	m_buffer = std::unique_ptr<char>(new char[bytes]);
	proc.readBlob(valueAs<long*>(), m_buffer.get(), bytes);

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
			cur->d_off,
			// to avoid copying we only keep a string_view in
			// Entry pointing to the raw buffer data.
			std::string_view{cur->d_name, namelen},
			cosmos::DirEntry::Type{static_cast<unsigned char>(type)}
		});
		pos += cur->d_reclen;
	}
}

} // end ns
