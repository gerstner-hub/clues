// clues
#include <clues/syscalls/process.hxx>

namespace clues {

void CloneSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	m_pars.erase(m_pars.begin() + 2, m_pars.end());

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
			child_tid.emplace("child_tid",
					"pointer to child TID in child's memory");
			maybe_add_unused_par(pos);
			addParameters(*child_tid);
		}
	};

	auto maybe_add_settls_par = [this, clone_flags, maybe_add_unused_par](const size_t pos) {
		if (clone_flags[SETTLS]) {
			tls.emplace("tls", "ABI-specific thread-local-storage data");

			maybe_add_unused_par(pos);
			addParameters(*tls);
		}
	};

	// these two are mutual-exclusive in the old clone() system call
	if (clone_flags[PARENT_SETTID]) {
		parent_tid.emplace("parent_tid",
				"pointer to child TID in parent's memory");
		addParameters(*parent_tid);
	} else if (clone_flags[PIDFD]) {
		pidfd.emplace("pidfd",
				"pointer to pidfd in parent's memory (alternative use of parent_tid)");
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

} // end ns
