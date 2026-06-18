// clues
#include <clues/syscalls/prctl.hxx>
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

void PrCtlSystemCall::setBoolReturn() {
	bool_res.emplace("bool", "", ItemType::RETVAL);
	setReturnItem(*bool_res);
}

void PrCtlSystemCall::setSuccessReturn() {
	res.emplace();
	setReturnItem(*res);
}

bool PrCtlSystemCall::check2ndPass(const Tracee &) {
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
	 * MPX_ENABLE/DISABLE_MANAGEMENT: dropped in kernel 5.4.
	 */

	switch (op.operation()) {
		case GET_DUMPABLE: /* fallthrough */
		case GET_IO_FLUSHER: /* fallthrough */
		case GET_NO_NEW_PRIVS: /* fallthrough */
		case GET_KEEPCAPS: {
			set_bool_return();
			break;
		} case SET_DUMPABLE: /* fallthrough */
		  case SET_IO_FLUSHER: /* fallthrough */
		  case SET_CHILD_SUBREAPER: /* fallthrough */
		  case SET_NO_NEW_PRIVS: /* fallthrough */
		  case SET_KEEPCAPS: {
			bool_setting.emplace("state", "new attribute state");
			addParameters(*bool_setting);
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

	clearOptArgs();
	clearOptRetVals();
}

void PrCtlSystemCall::clearOptArgs() {
	bool_setting.reset();
}

void PrCtlSystemCall::clearOptRetVals() {
	res.reset();
	bool_res.reset();
}

SystemCallPtr PrCtlSystemCall::createSystemCall(const SystemCallInfo &info) {

	using enum item::ProcessOp::Operation;
	using namespace clues::prctl;

	const auto op = item::ProcessOp::Operation(info.entryInfo()->args()[0]);

	switch (op) {
		case SET_MM: return std::make_shared<MemoryMapSystemCall>();
		case MCE_KILL: return std::make_shared<
			       MachineCheckKillSystemCall>();
		case MCE_KILL_GET:
			return std::make_shared<
				MachineCheckKillGetSystemCall>();
		case CAP_AMBIENT:
			return std::make_shared<CapAmbientSystemCall>();
		case CAPBSET_READ: /* fallthrough */
		case CAPBSET_DROP:
			return std::make_shared<CapBSetSystemCall>();
		case GET_CHILD_SUBREAPER:
			return std::make_shared<GetChildSubReaperSystemCall>();
		case SET_VMA:
			return std::make_shared<VirtualMemoryAttrSystemCall>();
		case GET_NAME: /* fallthrough */
		case SET_NAME:
			return std::make_shared<NameSystemCall>();
		default: return std::make_shared<PrCtlSystemCall>();
	}
}

namespace prctl {

bool MemoryMapSystemCall::check2ndPass(const Tracee&) {
	using enum item::MemoryMapOp::Operation;

	switch (mm_op.operation()) {
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
			addr.emplace("addr");
			addParameters(*addr);
			break;
		case MAP_SIZE:
			reported_size.emplace("size");
			addParameters(*reported_size);
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

	return true;
}

void MemoryMapSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 2, m_pars.end());
	PrCtlSystemCall::clearOptArgs();

	addr.reset();
	reported_size.reset();
	exe_fd.reset();
	mm_struct.reset();
	mm_struct_size.reset();
}

void MachineCheckKillSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 2, m_pars.end());
	PrCtlSystemCall::clearOptArgs();
	policy.reset();
}

bool MachineCheckKillSystemCall::check2ndPass(const Tracee &) {
	if (mce_kill_op.operation() == item::MachineCheckOp::SET) {
		policy.emplace();
		addParameters(*policy);
		return true;
	}

	return false;
}

void MachineCheckKillGetSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 1, m_pars.end());
	PrCtlSystemCall::clearOptArgs();
}

void CapAmbientSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 2, m_pars.end());
	PrCtlSystemCall::clearOptArgs();
	PrCtlSystemCall::clearOptRetVals();
	cap.reset();
}

bool CapAmbientSystemCall::check2ndPass(const Tracee &) {
	using SubOp = item::AmbientCapOp;
	const auto sub_op = ambient_op.operation();

	if (sub_op != SubOp::CLEAR_ALL) {
		// we need an additional capability parameter
		cap.emplace();
		addParameters(*cap);
	}

	if (sub_op == SubOp::IS_SET) {
		// here we need a bool return, keep the
		// default otherwise
		setBoolReturn();
	} else {
		setSuccessReturn();
	}

	return true;
}

void CapBSetSystemCall::prepareNewSystemCall() {
	PrCtlSystemCall::clearOptRetVals();
}

bool CapBSetSystemCall::check2ndPass(const Tracee &) {
	using enum item::ProcessOp::Operation;

	switch (op.operation()) {
		case CAPBSET_READ: {
			setBoolReturn();
			break;
		} case CAPBSET_DROP: {
			setSuccessReturn();
			break;
		} default: {
			throw cosmos::RuntimeError{"bad prctl op"};
		}
	}

	return true;
}

bool NameSystemCall::check2ndPass(const Tracee&) {
	using enum item::ProcessOp::Operation;

	switch (op.operation()) {
		case GET_NAME: {
			name.emplace("name", "process name", ItemType::PARAM_OUT);
			break;
		} case SET_NAME: {
			name.emplace("name", "process name");
			break;
		} default: {
			throw cosmos::RuntimeError{"bad prctl op"};
		}
	}

	addParameters(*name);

	return true;
}

void NameSystemCall::prepareNewSystemCall() {
	m_pars.erase(m_pars.begin() + 1, m_pars.end());
}

} // end ns prctl

} // end ns
