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

bool ArchPrctlSystemCall::check2ndPass() {

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
		set_addr.emplace(item::ULongValue{"base"});
		set_addr->setBase(Base::HEX);
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

} // end ns
