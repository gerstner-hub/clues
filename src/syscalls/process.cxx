// clues
#include <clues/syscalls/process.hxx>
#include <clues/Tracee.hxx>

namespace clues {

void CloneSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	dropParameters(2);

	/* args */
	parent_tid.reset();
	pidfd.reset();
	child_tid.reset();
	tls.reset();
}

bool CloneSystemCall::check2ndPass(const Tracee &)  {
	// we need these two sizes to match, since a `pid_t*` is used in
	// clone() to store either the child pid or a pidfd at.
	static_assert( sizeof(int) == sizeof(pid_t), "sizeof(int) != sizeof(pid_t)" );
	using enum cosmos::CloneFlag;
	const auto clone_flags = this->flags.flags();

	auto maybe_add_unused_par = [this](const size_t need_index) {
		while (need_index > m_pars.size()) {
			addParameters(item::unused);
		}
	};

	auto maybe_add_settid_par = [this, clone_flags, maybe_add_unused_par](const size_t pos) {
		if (clone_flags[CHILD_SETTID]) {
			child_tid.emplace(ItemCfg{.label = "child_tid",
					.desc = "pointer to child TID in child's memory"});
			maybe_add_unused_par(pos);
			addParameters(*child_tid);
		}
	};

	auto maybe_add_settls_par = [this, clone_flags, maybe_add_unused_par](const size_t pos) {
		if (clone_flags[SETTLS]) {
			tls.emplace(ItemCfg{.label = "tls",
					.desc = "ABI-specific thread-local-storage data"});

			maybe_add_unused_par(pos);
			addParameters(*tls);
		}
	};

	// these two are mutual-exclusive in the old clone() system call
	if (clone_flags[PARENT_SETTID]) {
		parent_tid.emplace(ItemCfg{.label = "parent_tid",
				.desc = "pointer to child TID in parent's memory"});
		addParameters(*parent_tid);
	} else if (clone_flags[PIDFD]) {
		pidfd.emplace(ItemCfg{.label = "pidfd",
				.desc = "pointer to pidfd in parent's memory (alternative use of parent_tid)"});
		addParameters(*pidfd);
	}

	/*
	 * Things are messy with clone(), the order of parameters differs
	 * between ABIs and we might need to skip some parameters by adding
	 * item::unused.
	 *
	 * The man page is a bit sketchy on the ABI details. In the kernel
	 * source we have to look for `CONFIG_CLONE_BACKWARDS*`, define in
	 * "arch/.../KConfig" as CLONE_BACKWARDS*.
	 *
	 * The situation for the ABIs we support is as follows:
	 *
	 * X86_32 (I386), ARM, ARM64: CLONE_BACKWARDS
	 * X86_64 (seems to include X32): no define
	 *
	 * CLONE_BACKWARDS means the final two arguments are tls /
	 * child_tidptr.
	 *
	 * no define means the final two arguments are child_tidptr / tls.
	 */

	if (const auto abi = this->abi(); abi == ABI::X86_64 || abi == ABI::X32) {
		maybe_add_settid_par(3);
		maybe_add_settls_par(4);
	} else if (abi == ABI::AARCH64 || abi == ABI::I386) {
		maybe_add_settls_par(3);
		maybe_add_settid_par(4);
	}

	return m_pars.size() > 2;
}

void Clone3SystemCall::updateFDTracking(const Tracee &proc) {
	const auto args = cl_args.args();

	if (!args) {
		return;
	} else if (args->flags()[cosmos::CloneFlag::PIDFD]) {
		FDInfo info{FDInfo::Type::PID_FD, cl_args.pidfd()};
		trackFD(proc, std::move(info));
	}
}

bool WaitIDSystemCall::check2ndPass(const Tracee&) {
	using Type = item::WaitID::Type;

	auto setup_pars = [this](auto &dynpar) {
		addParameters(dynpar, siginfo, options, rusage);
	};

	switch (idtype.type()) {
		case Type::PID: {
			id_pid.emplace();
			setup_pars(*id_pid);
			break;
		} case Type::PGID: {
			id_pgid.emplace();
			setup_pars(*id_pgid);
			break;
		} case Type::PIDFD: {
			id_pidfd.emplace(ItemCfg{
					.label = "pidfd",
					.desc = "pid file descriptor"},
					item::AtSemantics{false});
			setup_pars(*id_pidfd);
			break;
		} case Type::ALL: {
			/* id parameter remains unused in this case */
			setup_pars(item::unused);
			break;
		} default:
			throw cosmos::RuntimeError{"unsupported WaitID encountered"};
	}

	return true;
}

void WaitIDSystemCall::prepareNewSystemCall() {
	dropParameters(1);
	id_pid.reset();
	id_pgid.reset();
	id_pidfd.reset();
}

void PIDFDOpenSystemCall::updateFDTracking(const Tracee &proc) {
	auto info = FDInfo{FDInfo::PID_FD, new_fd.fd()};

	if (flags.flags()[cosmos::ProcessFile::OpenFlag::NONBLOCK]) {
		info.flags.emplace(cosmos::OpenFlag::NONBLOCK);
	}

	trackFD(proc, std::move(info));
}

void PIDFDGetFDSystemCall::updateFDTracking(const Tracee &proc) {
	/*
	 * it's difficult in this context, since we can duplicate an arbitrary
	 * target file descriptor and we're not necessarily tracing the target
	 * process, so races can occur.
	 *
	 * best we can do is looking up our own /proc to determine the new
	 * descriptor type.
	 */

	try {
		const auto our_fd = new_fd.fd();
		for (auto &info: get_fd_infos(proc.pid())) {
			if (info.fd == our_fd) {
				trackFD(proc, std::move(info));
				break;
			}
		}

	} catch (...) {
		/*
		 * Probably the tracee died unexpectedly. Let's use an unknown
		 * FD type in this case.
		 */
		trackFD(proc, FDInfo{FDInfo::UNKNOWN, new_fd.fd()});
		return;
	}

}

} // end ns
