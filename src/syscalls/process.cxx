// clues
#include <clues/syscalls/process.hxx>

namespace clues {

void ArchPrctlSystemCall::prepareNewSystemCall() {
	// only keep the `op` parameter
	m_pars.erase(m_pars.begin() + 1, m_pars.end());

	on_off.reset();
	set_addr.reset();
	get_addr.reset();

	on_off_ret.reset();
	result.emplace(item::SuccessResult{});
	setReturnItem(*result);
}

bool ArchPrctlSystemCall::check2ndPass(const Tracee &) {

	using enum item::ArchOpParameter::Operation;

	switch (op.operation()) {
	case SET_CPUID:
		on_off.emplace(item::ULongValue{"enable"});
		addParameters(*on_off);
		break;
	case GET_CPUID:
		result.reset();
		on_off_ret.emplace(item::IntValue{"enabled?", "", ItemType::RETVAL});
		setReturnItem(*on_off_ret);
		break;
	case SET_FS: [[fallthrough]];
	case SET_GS:
		set_addr.emplace(item::GenericPointerValue{"base"});
		addParameters(*set_addr);
		break;
	case GET_FS: [[fallthrough]];
	case GET_GS:
		get_addr.emplace(item::PointerToScalar<unsigned long>{"*base"});
		get_addr->setBase(Base::HEX);
		addParameters(*get_addr);
		break;
	default: /* unknown operation? keep defaults */
		break;
	}

	return true;
}

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
			child_tid.emplace(item::GenericPointerValue{"child_tid", "pointer to child TID in child's memory"});
			maybe_add_unused_par(pos);
			addParameters(*child_tid);
		}
	};

	auto maybe_add_settls_par = [this, clone_flags, maybe_add_unused_par](const size_t pos) {
		if (clone_flags[SETTLS]) {
			tls.emplace(item::GenericPointerValue{"tls", "ABI-specific thread-local-storage data"});

			maybe_add_unused_par(pos);
			addParameters(*tls);
		}
	};

	// these two are mutual-exclusive in the old clone() system call
	if (clone_flags[PARENT_SETTID]) {
		parent_tid.emplace(item::PointerToScalar<cosmos::ProcessID>{
				"parent_tid", "pointer to child TID in parent's memory"});
		addParameters(*parent_tid);
	} else if (clone_flags[PIDFD]) {
		pidfd.emplace(item::PointerToScalar<cosmos::FileNum>{
				"pidfd", "pointer to pidfd in parent's memory (alternative use of parent_tid)"});
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
