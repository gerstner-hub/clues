// clues
#include <clues/format.hxx>
#include <clues/items/clone.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>
#include <clues/Tracee.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

namespace {

std::string clone_flags_str(const cosmos::CloneFlags flags, const std::optional<cosmos::SignalNr> exit_signal = {}) {
	BITFLAGS_FORMAT_START(flags);

	BITFLAGS_ADD(CLONE_CHILD_CLEARTID);
	BITFLAGS_ADD(CLONE_CHILD_SETTID);
	BITFLAGS_ADD(CLONE_CLEAR_SIGHAND);
	BITFLAGS_ADD(CLONE_DETACHED);
	BITFLAGS_ADD(CLONE_FILES);
	BITFLAGS_ADD(CLONE_FS);
	BITFLAGS_ADD(CLONE_INTO_CGROUP);
	BITFLAGS_ADD(CLONE_IO);
	BITFLAGS_ADD(CLONE_NEWCGROUP);
	BITFLAGS_ADD(CLONE_NEWIPC);
	BITFLAGS_ADD(CLONE_NEWNET);
	BITFLAGS_ADD(CLONE_NEWNS);
	BITFLAGS_ADD(CLONE_NEWNS);
	BITFLAGS_ADD(CLONE_NEWPID);
	BITFLAGS_ADD(CLONE_NEWUSER);
	BITFLAGS_ADD(CLONE_NEWUTS);
	BITFLAGS_ADD(CLONE_PARENT);
	BITFLAGS_ADD(CLONE_PARENT_SETTID);
	BITFLAGS_ADD(CLONE_PIDFD);
	BITFLAGS_ADD(CLONE_PTRACE);
	BITFLAGS_ADD(CLONE_SETTLS);
	BITFLAGS_ADD(CLONE_SIGHAND);
	BITFLAGS_ADD(CLONE_SYSVSEM);
	BITFLAGS_ADD(CLONE_THREAD);
	BITFLAGS_ADD(CLONE_UNTRACED);
	BITFLAGS_ADD(CLONE_VFORK);
	BITFLAGS_ADD(CLONE_VM);

	if (exit_signal) {
		BITFLAGS_STREAM() << format::signal(*exit_signal, /*verbose=*/false);
	}

	return BITFLAGS_STR();
}

}

std::string CloneFlagsValue::str() const {
	return clone_flags_str(m_flags, exit_signal);
}

void CloneFlagsValue::processValue(const Tracee &) {
	if (m_call->callNr() == SystemCallNr::CLONE) {
		// child exit signal is piggy-backed in the low byte of flags
		// although clone(2) shows an `int` here, this is a 64-bit flags typetype
		const auto raw = valueAs<uint64_t>();
		// CloneFlags are based on uint64_t (type used in clone3()),
		// thus cast accordingly.
		m_flags = cosmos::CloneFlags{static_cast<uint64_t>(raw & (~0xFF))};
		exit_signal.emplace(cosmos::SignalNr{static_cast<int>(raw) & 0xFF});
	} else {
		m_flags = valueAs<cosmos::CloneFlags>();
		exit_signal.reset();
	}
}

void CloneArgs::resetArgs() {
	m_pidfd = cosmos::FileNum::INVALID;
	m_cgroup2_fd = cosmos::FileNum::INVALID;
	m_child_tid = cosmos::ThreadID::INVALID;
	m_tid_array.clear();
	m_args.reset();
}

void CloneArgs::processValue(const Tracee &proc) {

	resetArgs();

	if (!verifySize())
		return;

	m_args.emplace(cosmos::CloneArgs{});

	// ignore the check for trivial types, cosmos::CloneArgs has a
	// constructor to set the whole structure to zero, we can live with that
	// not happening here.
	if (!proc.readStruct<cosmos::CloneArgs, /*CHECK_TRIVIAL=*/false>(asPtr(), *m_args)) {
		m_args.reset();
		return;
	}

	const auto &args = *m_args;
	const auto raw = args.raw();
	const auto num_tids = raw->set_tid_size;

	if (num_tids > 0) {
		m_tid_array.resize(num_tids);
		try {
			proc.readBlob(
					ForeignPtr{static_cast<uintptr_t>(raw->set_tid)},
					reinterpret_cast<char*>(m_tid_array.data()), num_tids * sizeof(cosmos::ThreadID));
		} catch (const std::exception &ex) {
			// could be an invalid userspace pointer
			m_tid_array.clear();
		}
	}

	if (args.isSet(cosmos::CloneFlag::INTO_CGROUP)) {
		m_cgroup2_fd = args.cgroup().raw();
	}
}

void CloneArgs::updateData(const Tracee &proc) {

	if (!m_args)
		return;

	const auto &args = *m_args;
	const auto raw = args.raw();
	const auto flags = args.flags();
	using enum cosmos::CloneFlag;

	if (flags[PIDFD]) {
		// read the assigned PID file descriptor from tracee memory.
		proc.readStruct(ForeignPtr{static_cast<uintptr_t>(raw->pidfd)}, m_pidfd);
	}

	if (flags[PARENT_SETTID]) {
		proc.readStruct(ForeignPtr{static_cast<uintptr_t>(raw->parent_tid)}, m_child_tid);
	}
}

bool CloneArgs::verifySize() const {
	if (m_call->callNr() == SystemCallNr::CLONE3) {
		/* we need to make a forward lookup of the size argument,
		 * which follows the cl_args parameter */
		const auto info = *m_call->currentInfo()->entryInfo();

		if (info.args()[1] < sizeof(cosmos::CloneArgs)) {
			return false;
		}

		return true;
	} else {
		// yet unknown system call?
		return false;
	}
}

std::string CloneArgs::str() const {
	if (!m_args) {
		if (isZero())
			return "NULL";
		else
			// verifySize() failed
			return format::pointer(asPtr()) + " (size mismatch)";
	}

	auto uint2ptr = [](uint64_t val) -> ForeignPtr {
		return ForeignPtr{static_cast<uintptr_t>(val)};
	};

	std::stringstream ss;
	const auto &args = *m_args;
	const auto flags = args.flags();
	const auto raw = args.raw();
	using enum cosmos::CloneFlag;

	ss << "{";
	ss << "flags=" << clone_flags_str(flags);
	if (flags[PIDFD]) {
		ss << ", pidfd=" << format::pointer(uint2ptr(raw->pidfd), std::to_string(cosmos::to_integral(m_pidfd)));
	}
	if (flags[CHILD_CLEARTID] || flags[CHILD_SETTID]) {
		const auto child_tid_ptr = ForeignPtr{reinterpret_cast<uintptr_t>(args.childTID())};
		ss << ", child_tid=" << format::pointer(child_tid_ptr);
	}
	if (flags[PARENT_SETTID]) {
		const auto parent_tid_ptr = ForeignPtr{reinterpret_cast<uintptr_t>(args.parentTID())};
		ss << ", parent_tid=" << format::pointer(parent_tid_ptr,
				std::to_string(cosmos::to_integral(m_child_tid)));
	}
	ss << ", exit_signal=" << format::signal(args.exitSignal().raw(), /*verbose=*/false);
	const auto stack_ptr = ForeignPtr{reinterpret_cast<uintptr_t>(args.stack())};
	ss << ", stack=" << format::pointer(stack_ptr);
	ss << ", stack_size=" << args.stackSize();
	if (flags[SETTLS]) {
		// this is a architecture dependent value, interpreting it as
		// a hex pointer should be good enough for now.
		ss << ", tls=" << format::pointer(uint2ptr(raw->tls));
	}

	const auto settid_ptr = uint2ptr(raw->set_tid);
	if (raw->set_tid_size) {
		std::stringstream ss2;
		std::string sep = "";
		for (const auto tid: m_tid_array) {
			ss2 << sep;
			ss2 << cosmos::to_integral(tid);
			if (sep.empty())
				sep = ", ";
		}
		ss << ", set_tid=" << format::pointer(settid_ptr, ss2.str()); 
	} else {
		/*
		 * don't evaluate the pointed-to data in this case, but it
		 * could still be interesting to know if some strange value is
		 * passed here alongside the 0 size.
		 */
		ss << ", set_tid=" << format::pointer(settid_ptr);
	}
	ss << ", set_tid_size=" << raw->set_tid_size;

	if (flags[INTO_CGROUP]) {
		ss << ", cgroup=" << cosmos::to_integral(m_cgroup2_fd);
	}

	ss << "}";

	return ss.str();
}

} // end ns
