// clues
#include <clues/syscalls/fs.hxx>

namespace clues {

void FcntlSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	m_pars.erase(m_pars.begin() + 2, m_pars.end());

	// setup the default return value
	result.emplace(item::SuccessResult{});
	setReturnItem(*result);

	/* args */
	dup_num.reset();
	fd_flags_arg.reset();
	status_flags_arg.reset();
	flock_arg.reset();

	/* retvals */
	dupfd.reset();
	ret_fd_flags.reset();
	ret_status_flags.reset();
}

bool FcntlSystemCall::check2ndPass() {
	auto setExtraParameter = [this](auto &extra_par) {
		setParameters(extra_par);
	};
	auto setNewReturnItem = [this](auto &new_ret) {
		result.reset();
		setReturnItem(new_ret);
	};

	using Oper = item::FcntlOperation::Oper;
	switch (operation.operation()) {
		case Oper::DUPFD: [[fallthrough]];
		case Oper::DUPFD_CLOEXEC: {
			dup_num.emplace(item::FileDescriptor{ItemType::PARAM_IN, item::AtSemantics{false},
				"lowest_fd", "lowest dup file descriptor number"});
			dupfd.emplace(item::FileDescriptor{ItemType::RETVAL, item::AtSemantics{false},
				"dupfd", "duplicated file descriptor"});
			setNewReturnItem(*dupfd);
			setExtraParameter(*dup_num);
			break;
		} case Oper::GETFD: {
			ret_fd_flags.emplace(item::FileDescFlagsValue{ItemType::RETVAL});
			setNewReturnItem(*ret_fd_flags);
			break;
		} case Oper::SETFD: {
			fd_flags_arg.emplace(item::FileDescFlagsValue{ItemType::PARAM_IN});
			setExtraParameter(*fd_flags_arg);
			break;
		} case Oper::GETFL: {
			ret_status_flags.emplace(item::OpenFlagsValue{ItemType::RETVAL});
			setNewReturnItem(*ret_status_flags);
			break;
		} case Oper::SETFL: {
			status_flags_arg.emplace(item::OpenFlagsValue{ItemType::PARAM_IN});
			setExtraParameter(*status_flags_arg);
			break;
		} case Oper::SETLK: [[fallthrough]];
		  case Oper::SETLKW: [[fallthrough]];
		  case Oper::GETLK: [[fallthrough]];
		  case Oper::OFD_SETLK: [[fallthrough]];
		  case Oper::OFD_SETLKW: [[fallthrough]];
		  case Oper::OFD_GETLK: {
			/*
			 * OFD locks and old style locks use the same API
			 * details
			 */
			flock_arg.emplace(item::FLockParameter{});
			setExtraParameter(*flock_arg);
			break;
		} default: {
			/* keep defaults */
			break;
		}
	}

	return true;
}

} // end ns
