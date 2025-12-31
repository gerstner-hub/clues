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
	if (!m_op) {
		throw cosmos::RuntimeError{"no operation stored"};
	}

	switch (cosmos::to_integral(*m_op)) {
		CASE_ENUM_TO_STR(F_DUPFD);
		CASE_ENUM_TO_STR(F_DUPFD_CLOEXEC);
		CASE_ENUM_TO_STR(F_GETFD);
		CASE_ENUM_TO_STR(F_SETFD);
		CASE_ENUM_TO_STR(F_GETFL);
		CASE_ENUM_TO_STR(F_SETFL);
		CASE_ENUM_TO_STR(F_SETLK);
		CASE_ENUM_TO_STR(F_SETLKW);
		CASE_ENUM_TO_STR(F_GETLK);
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
		default: return "???";
	}
}

void FLockParameter::processValue(const Tracee &proc) {
	/* all flock related operations provide input, so unconditionally
	 * process it */

	// TODO: handle flock32 case on i386 & friends

	clues::flock64 lock;

	if (!proc.readStruct(m_val, lock)) {
		m_lock.reset();
		return;
	}

	if (!m_lock) {
		m_lock = std::make_optional<cosmos::FileLock>(cosmos::FileLock::Type::READ_LOCK);
	}

	m_lock->l_type = lock.l_type;
	m_lock->l_whence = lock.l_whence;
	m_lock->l_start = lock.l_start;
	m_lock->l_len = lock.l_len;
	m_lock->l_pid = lock.l_pid;
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
		default: return "???";
	}
}

std::string FLockParameter::str() const {
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

	if (!proc.readStruct(m_val, *m_owner->raw())) {
		m_owner.reset();
	}
}

void LeaseType::processValue(const Tracee &) {
	m_lease = cosmos::FileDescriptor::LeaseType{valueAs<int>()};
}

std::string LeaseType::str() const {
	return std::string{lock_type_to_str(cosmos::to_integral(*m_lease))};
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
	if (proc.readStruct(m_val, native_hint)) {
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
