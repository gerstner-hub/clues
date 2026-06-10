// clues
#include <clues/syscalls/process.hxx>
#include <clues/SystemCallInfo.hxx>

namespace clues {

#ifdef CLUES_HAVE_ARCH_PRCTL
void ArchPrctlSystemCall::prepareNewSystemCall() {
	// only keep the `op` parameter
	m_pars.erase(m_pars.begin() + 1, m_pars.end());

	on_off.reset();
	set_addr.reset();
	get_addr.reset();

	on_off_ret.reset();
	result.emplace();
	setReturnItem(*result);
}

bool ArchPrctlSystemCall::check2ndPass(const Tracee &) {

	using enum item::ArchOpParameter::Operation;

	switch (op.operation()) {
	case SET_CPUID:
		on_off.emplace("enable");
		addParameters(*on_off);
		break;
	case GET_CPUID:
		result.reset();
		on_off_ret.emplace("enabled?", "", ItemType::RETVAL);
		setReturnItem(*on_off_ret);
		break;
	case SET_FS: [[fallthrough]];
	case SET_GS:
		set_addr.emplace("base");
		addParameters(*set_addr);
		break;
	case GET_FS: [[fallthrough]];
	case GET_GS:
		get_addr.emplace("*base");
		get_addr->setBase(Base::HEX);
		addParameters(*get_addr);
		break;
	default: /* unknown operation? keep defaults */
		break;
	}

	return true;
}
#endif

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

bool PrCtlSystemCall::check2ndPass(const Tracee &proc) {
	using enum item::ProcessOp::Operation;

	auto set_bool_return = [this]() {
		bool_res.emplace("bool", "", ItemType::RETVAL);
		setReturnItem(*bool_res);
	};

	/*
	 * TODO:
	 *
	 * GET7SET_ENDIAN PowerPC only
	 * GET/SET_FP_MODE MIPS only
	 * GET/SET_FP_EMDU IA64 only
	 * GET/SET_FP_EXC PowerPC only
	 */

	switch (*op.operation()) {
		case CAPBSET_READ: {
			cap.emplace();
			addParameters(*cap);
			set_bool_return();
			break;
		} case CAPBSET_DROP: {
			cap.emplace();
			addParameters(*cap);
			/* use default return value */
			break;
		} case CAP_AMBIENT: {
			using SubOp = item::AmbientCapOp;
			ambient_op.emplace();
			addParameters(*ambient_op);
			const auto data = m_info->argAsWord(1);
			/*
			 * we need to know the sub-operation to further deduce
			 * the return type and additional parameters.
			 */
			ambient_op->fill(proc, data);

			const auto sub_op = ambient_op->operation();

			if (sub_op != SubOp::CLEAR_ALL) {
				// we need an additional capability parameter
				cap.emplace();
			}

			if (sub_op == SubOp::IS_SET) {
				// here we need a bool return, keep the
				// default otherwise
				set_bool_return();
			}

			if (cap) {
				addParameters(*cap);
			}
			break;
		} case GET_CHILD_SUBREAPER: {
			is_subreaper.emplace("subreaper", "is child-subreaper");
			addParameters(*is_subreaper);
			break;
		} case GET_DUMPABLE: /* fallthrough */
		  case GET_IO_FLUSHER: /* fallthrough */
		  case GET_KEEPCAPS: {
			set_bool_return();
			break;
		} case SET_DUMPABLE: /* fallthrough */
		  case SET_IO_FLUSHER: /* fallthrough */
		  case SET_CHILD_SUBREAPER: /* fallthrough */
		  case SET_KEEPCAPS: {
			bool_setting.emplace("state", "new attribute state");
			addParameters(*bool_setting);
			break;
		} case MCE_KILL: {
			mce_op.emplace();
			addParameters(*mce_op);
			const auto data = m_info->argAsWord(1);
			/*
			 * we need to know the sub-operation to further deduce
			 * possible additional parameters.
			 */
			mce_op->fill(proc, data);

			if (mce_op->operation() == item::MachineCheckOp::SET) {
				mce_policy.emplace();
				addParameters(*mce_policy);
			}
			break;
		} case MCE_KILL_GET: {
			mce_policy_res.emplace(ItemType::RETVAL);
			setReturnItem(*mce_policy_res);
			break;
		} case SET_MM: {
			mm_op.emplace();
			addParameters(*mm_op);
			const auto data = m_info->argAsWord(1);
			/* we need to know the sub-operation to further decude
			 * possible additional parameters */
			mm_op->fill(proc, data);

			using enum item::MemoryMapOp::Operation;

			switch (*mm_op->operation()) {
				case START_CODE:
				case END_CODE:
				case START_DATA:
				case END_DATA:
				case START_STACK:
				case START_BRK:
				case BRK:
				case ARG_START:
				case ARG_END:
				case ENV_START:
				case ENV_END:
				case AUXV:
					mm_addr.emplace("addr");
					addParameters(*mm_addr);
					break;
				case MAP_SIZE:
					map_size.emplace("size");
					addParameters(*map_size);
					break;
				case EXE_FILE:
					exe_fd.emplace();
					addParameters(*exe_fd);
					break;
				case MAP:
					mm_struct.emplace();
					mm_struct_size.emplace("size",
							"size of struct prctl_mm_map");
					addParameters(*mm_struct, *mm_struct_size);
					break;
			}
			break;
		} default: {
			break;
		}
	}

	if (!m_return) {
		res.emplace();
		setReturnItem(*res);
	}

	return true;
}

void PrCtlSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 1, m_pars.end());
	m_return = nullptr;

	res.reset();
	bool_res.reset();
	mce_policy_res.reset();

	cap.reset();
	ambient_op.reset();
	mce_op.reset();
	mce_policy.reset();
	is_subreaper.reset();
	bool_setting.reset();
	mm_op.reset();
	mm_addr.reset();
	map_size.reset();
	exe_fd.reset();
	mm_struct.reset();
	mm_struct_size.reset();
}

} // end ns
