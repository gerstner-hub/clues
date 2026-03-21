// C++
#include <sstream>

// cosmos
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/formatting.hxx>

// clues
#include <clues/Tracee.hxx>
#include <clues/items/fcntl.hxx>
#include <clues/kernel_structs.hxx>
#include <clues/macros.h>
#include <clues/private/utils.hxx>
#include <clues/syscalls/fs.hxx>

namespace clues::item {

std::string FileDescFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(FD_CLOEXEC);

	return BITFLAGS_STR();
}

void FileDescFlagsValue::processValue(const Tracee &) {
	m_flags = cosmos::FileDescriptor::DescFlags{valueAs<int>()};
}

void FcntlOperation::processValue(const Tracee &) {
	m_op = valueAs<Oper>();
}

std::string FcntlOperation::str() const {
	/*
	 * the F_*LK definitions exported by userspace headers are not helpful
	 * for our tracer context at all. They have different values on 64-bit
	 * targets than on 32-bit targets without _FILE_OFFSET_BITS=64 than on
	 * 32-bit targets with the latter define. They don't relate to what
	 * happens on system call level at all.
	 *
	 * Thus get rid of the macro definitions and use our own literal
	 * constants.
	 */
#pragma push_macro("F_GETLK")
#pragma push_macro("F_GETLK64")
#pragma push_macro("F_SETLK")
#pragma push_macro("F_SETLK64")
#pragma push_macro("F_SETLKW")
#pragma push_macro("F_SETLKW64")
#undef F_GETLK
#undef F_SETLK
#undef F_SETLKW
#undef F_GETLK64
#undef F_SETLK64
#undef F_SETLKW64

	constexpr int F_GETLK    = cosmos::to_integral(Oper::GETLK);
	constexpr int F_GETLK64  = cosmos::to_integral(Oper::GETLK64);
	constexpr int F_SETLK    = cosmos::to_integral(Oper::SETLK);
	constexpr int F_SETLK64  = cosmos::to_integral(Oper::SETLK64);
	constexpr int F_SETLKW   = cosmos::to_integral(Oper::SETLKW);
	constexpr int F_SETLKW64 = cosmos::to_integral(Oper::SETLKW64);

	switch (cosmos::to_integral(m_op)) {
		CASE_ENUM_TO_STR(F_DUPFD);
		CASE_ENUM_TO_STR(F_DUPFD_CLOEXEC);
		CASE_ENUM_TO_STR(F_GETFD);
		CASE_ENUM_TO_STR(F_SETFD);
		CASE_ENUM_TO_STR(F_GETFL);
		CASE_ENUM_TO_STR(F_SETFL);
		CASE_ENUM_TO_STR(F_GETLK);
		CASE_ENUM_TO_STR(F_SETLK);
		CASE_ENUM_TO_STR(F_SETLKW);
		CASE_ENUM_TO_STR(F_GETLK64);
		CASE_ENUM_TO_STR(F_SETLK64);
		CASE_ENUM_TO_STR(F_SETLKW64);
		CASE_ENUM_TO_STR(F_OFD_SETLK);
		CASE_ENUM_TO_STR(F_OFD_SETLKW);
		CASE_ENUM_TO_STR(F_OFD_GETLK);
		CASE_ENUM_TO_STR(F_GETOWN);
		CASE_ENUM_TO_STR(F_SETOWN);
		CASE_ENUM_TO_STR(F_GETOWN_EX);
		CASE_ENUM_TO_STR(F_SETOWN_EX);
		CASE_ENUM_TO_STR(F_GETSIG);
		CASE_ENUM_TO_STR(F_SETSIG);
		CASE_ENUM_TO_STR(F_SETLEASE);
		CASE_ENUM_TO_STR(F_GETLEASE);
		CASE_ENUM_TO_STR(F_NOTIFY);
		CASE_ENUM_TO_STR(F_SETPIPE_SZ);
		CASE_ENUM_TO_STR(F_GETPIPE_SZ);
		CASE_ENUM_TO_STR(F_ADD_SEALS);
		CASE_ENUM_TO_STR(F_GET_SEALS);
		CASE_ENUM_TO_STR(F_GET_RW_HINT);
		CASE_ENUM_TO_STR(F_SET_RW_HINT);
		CASE_ENUM_TO_STR(F_GET_FILE_RW_HINT);
		CASE_ENUM_TO_STR(F_SET_FILE_RW_HINT);
		default: return "F_???";
	}
#pragma pop_macro("F_GETLK")
#pragma pop_macro("F_GETLK64")
#pragma pop_macro("F_SETLK")
#pragma pop_macro("F_SETLK64")
#pragma pop_macro("F_SETLKW")
#pragma pop_macro("F_SETLKW64")
}

namespace kernel {

/*
 * to make things around `struct flock` still more confusing, there are
 * different alignments of the structure between i386 and x86_64 regarding
 * `struct flock64`. When compiled in 64-bit context it has 32 bytes
 * size, when compiled in 32-bit context it has 24 bytes size. For this reason
 * we need a dedicated compat flock64 when tracing 32-bit emulation binaries.
 * 
 * see also `compat_flock64` in include/linux/compat.h of the kernel sources.
 */
template <typename OFF_T>
struct flock_t {
	short l_type;
	short l_whence;
	OFF_T l_start;
	OFF_T l_len;
	pid_t l_pid;
} __attribute__((packed));

// 32-bit `off_t` structure which is only used on I386 with fcntl() or fcntl64() when passing GETLK/SETLK/SETLKW
using flock32 = flock_t<int32_t>;
// 64-bit `off_t` structure which is only used on I386 with fcntl64() when passing GETLK64/SETLK64/SETLKW64
using flock64_i386 = flock_t<int64_t>;

// 64-bit `off_t` structure which is used on 64-bit targets with flock()
struct flock64 {
	short l_type;
	short l_whence;
	uint64_t l_start;
	uint64_t l_len;
	pid_t l_pid;
};

} // end ns kernel

void FLockParameter::processValue(const Tracee &proc) {
	/* all flock related operations provide input, so unconditionally
	 * process it */

	/*
	 * The situation with fcntl() and fcntl64() is quite messy. fcntl64()
	 * only exists on 32-bit platforms like I386. The difference is only
	 * in the data structure used with the GETLK and SETLK operations.
	 *
	 * On 64-bit targets, with the single `fcntl()` system call these
	 * operations always take `struct flock` with 64-bit wide `off_t`. On
	 * i386 `fcntl()` takes `struct flock` with 32-bit wide `off_t`
	 * fields. `fcntl64` on the other hand can support both, the 32-bit
	 * wide and 64-bit wide `off_t` fields. To differentiate this,
	 * additional operations GETLK64, SETLK64 and SETLKW64 have been
	 * introduced. These operations are _only_ supported in `fcntl64` on
	 * 32-bit targets.
	 *
	 * To make things worse, the definition of F_GETLK and F_GETLK64 we
	 * get from the userspace headers depends on the following factors:
	 *
	 * - in a 64-bit compilation environment they're both always
	 *   set to 5,6,7, because `fcntl()` always uses struct
	 *   flock64 with 64-bit wide `off_t.
	 * - in a 32-bit compilation environment with
	 *   _FILE_OFFSET_BITS=64 they're always set to 12,13,14 so
	 *   that fcntl64 with struct flock64 is always used transparently.
	 * - in a 32-bit compilation environment _without_
	 *   _FILE_OFFSET_BITS=64 F_GETLK & friends are set to 5,6,7
	 *   and F_GETLK64 & friends are set to 12,13,14 allowing to
	 *   call regular fcntl() with 32-bit wide `off_t` and fcntl64() with
	 *   32-bit or 64-bit `off_t`.
	 *
	 * Thus these constants are a moving target depending on a lot
	 * of factors, which gets even more worse when a 64-bit tracer
	 * is looking at a 32-bit emulation binary. For this reason we are
	 * using our own literal values in FcntlOperation::Oper for the LK
	 * family of operations.
	 *
	 * The rule of thumb when looking at the raw system call is that on
	 * 64-bit targets either LK operation is always expecting a 64-bit
	 * `off_t` struct. On a 32-bit target like I386 the literal values
	 * 5,6,7 are always expecting a 32-bit `off_t` and the literal values
	 * 12,13,14 are always expecting a 64-bit `off_t` (and are only
	 * supported in `fcntl64()`).
	 *
	 * The OFD_ locks are not affected by this, they always use a 64-bit
	 * wide `off_t` in `struct flock`.
	 */

	cosmos::DeferGuard reset_lock{[this]() { m_lock.reset(); }};

	auto assign_data = [this, &reset_lock](const auto &lock) {
		if (!m_lock) {
			m_lock = std::make_optional<cosmos::FileLock>(cosmos::FileLock::Type::READ_LOCK);
		}

		m_lock->l_type = lock.l_type;
		m_lock->l_whence = lock.l_whence;
		m_lock->l_start = lock.l_start;
		m_lock->l_len = lock.l_len;
		m_lock->l_pid = lock.l_pid;
		reset_lock.disarm();
	};

	auto fetch_lock = [this, assign_data, &proc]<typename FLOCK>() {
		FLOCK lock;
		if (proc.readStruct(asPtr(), lock)) {
			assign_data(lock);
		}
	};

	if (const auto abi = m_call->abi(); abi != ABI::I386) {
		/*
		 * if the target ABI is 64-bit based then it's easy, simply
		 * use the only supported native 64-bit struct
		 */
		fetch_lock.operator()<kernel::flock64>();
		return;
	}

	// on i386 things get complicated

	if (const auto sysnr = m_call->callNr(); sysnr != SystemCallNr::FCNTL64) {
		/*
		 * for the old fcntl() call only the 32-bit `off_t` structure
		 * is supported. This one also has no alignment issues if the
		 * target is a 32-bit emulation binary.
		 */
		fetch_lock.operator()<kernel::flock32>();
		return;
	}

	/*
	 * for the fcntl64() call both 32-bit and 64-bit `off_t` are supported
	 * depending on the value found in the `op` parameter. Also we need to
	 * consider alignment for flock64 in case we're dealing with an
	 * emulation binary.
	 */
	auto fcntl_sys = dynamic_cast<const FcntlSystemCall*>(m_call);
	if (!fcntl_sys)
		// alien system call?
		return;

	if (fcntl_sys->operation.isLock64()) {
		// either native 32-bit tracing or the target is a 32-bit
		// emulation binary, we need i386 alignment in both cases
		fetch_lock.operator()<kernel::flock64_i386>();
	} else {
		/*
		 * with the 32-bit flock no alignment issues should occur when
		 * tracing emulation binaries
		 */
		fetch_lock.operator()<kernel::flock32>();
	}
}

void FLockParameter::updateData(const Tracee &proc) {
	const auto fcntl_sc = dynamic_cast<const FcntlSystemCall*>(m_call);
	if (!fcntl_sc || fcntl_sc->operation.operation() != item::FcntlOperation::Oper::GETLK) {
		// only the F_GETLK operation causes changes on output
		return;
	}

	processValue(proc);
}

template <typename INT>
static std::string_view lock_type_to_str(INT type) {
	switch (type) {
		CASE_ENUM_TO_STR(F_RDLCK);
		CASE_ENUM_TO_STR(F_WRLCK);
		CASE_ENUM_TO_STR(F_UNLCK);
		default: return "F_???";
	}
}

std::string FLockParameter::str() const {
	if (!m_lock) {
		return "<invalid>";
	}

	auto whence_str = [](short whence) {
		switch (whence) {
			CASE_ENUM_TO_STR(SEEK_SET);
			CASE_ENUM_TO_STR(SEEK_CUR);
			CASE_ENUM_TO_STR(SEEK_END);
			default: return "???";
		}
	};

	return cosmos::sprintf("{l_type=%s, l_whence=%s, l_start=%jd, l_len=%jd, l_pid=%d}",
			lock_type_to_str(cosmos::to_integral(m_lock->type())).data(),
			whence_str(cosmos::to_integral(m_lock->whence())),
			m_lock->start(),
			m_lock->start(),
			cosmos::to_integral(m_lock->pid())
	);
}

void FileDescOwner::processValue(const Tracee &) {
	const auto pid_or_pgid = valueAs<int>();

	if (pid_or_pgid >= 0) {
		m_pgid.reset();
		m_pid = cosmos::ProcessID{pid_or_pgid};
		m_short_name = "pid";
		m_long_name = "process id";
	} else {
		m_pid.reset();
		m_pgid = cosmos::ProcessGroupID{-pid_or_pgid};
		m_short_name = "pgid";
		m_long_name = "process group id";
	}
}

std::string FileDescOwner::str() const {
	if (m_pid)
		return std::to_string(cosmos::to_integral(*m_pid));
	else
		return std::to_string(cosmos::to_integral(*m_pgid));
}

std::string ExtFileDescOwner::str() const {
	if (!m_owner) {
		return "<invalid>";
	}

	auto type_str = [](cosmos::FileDescriptor::Owner::Type type) {
		switch (cosmos::to_integral(type)) {
			CASE_ENUM_TO_STR(F_OWNER_TID);
			CASE_ENUM_TO_STR(F_OWNER_PID);
			CASE_ENUM_TO_STR(F_OWNER_PGRP);
			default: return "???";
		}
	};

	std::stringstream ss;
	ss << "{type=" << type_str(m_owner->type()) << ", id=" << m_owner->raw()->pid << "}";
	return ss.str();
}

void ExtFileDescOwner::processValue(const Tracee &proc) {
	m_owner = cosmos::FileDescriptor::Owner{};

	if (!proc.readStruct(asPtr(), *m_owner->raw())) {
		m_owner.reset();
	}
}

void LeaseType::processValue(const Tracee &) {
	m_lease = cosmos::FileDescriptor::LeaseType{valueAs<int>()};
}

std::string LeaseType::str() const {
	return std::string{lock_type_to_str(cosmos::to_integral(m_lease))};
}

void DNotifySettings::processValue(const Tracee &) {
	m_settings = Settings{valueAs<int>()};
}

std::string DNotifySettings::str() const {
	BITFLAGS_FORMAT_START(m_settings);

	BITFLAGS_ADD(DN_ACCESS);
	BITFLAGS_ADD(DN_MODIFY);
	BITFLAGS_ADD(DN_CREATE);
	BITFLAGS_ADD(DN_DELETE);
	BITFLAGS_ADD(DN_RENAME);
	BITFLAGS_ADD(DN_ATTRIB);
	BITFLAGS_ADD(DN_MULTISHOT);

	return BITFLAGS_STR();
}

void FileSealSettings::processValue(const Tracee &) {
	m_flags = cosmos::FileDescriptor::SealFlags{valueAs<unsigned int>()};
}

std::string FileSealSettings::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(F_SEAL_SEAL);
	BITFLAGS_ADD(F_SEAL_SHRINK);
	BITFLAGS_ADD(F_SEAL_GROW);
	BITFLAGS_ADD(F_SEAL_WRITE);
	BITFLAGS_ADD(F_SEAL_FUTURE_WRITE);

	return BITFLAGS_STR();
}

void ReadWriteHint::processValue(const Tracee &proc) {
	/*
	 * this is used for both input and output parameter variants
	 */
	uint64_t native_hint;
	if (proc.readStruct(asPtr(), native_hint)) {
		m_hint = Hint{native_hint};
	} else {
		m_hint = Hint::LIFE_NOT_SET;
	}
}

std::string ReadWriteHint::str() const {
	switch (cosmos::to_integral(m_hint)) {
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_NOT_SET);
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_NONE);
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_SHORT);
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_MEDIUM);
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_LONG);
		CASE_ENUM_TO_STR(RWH_WRITE_LIFE_EXTREME);
		default: return "???";
	}
}

} // end ns
