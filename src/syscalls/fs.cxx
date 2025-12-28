// clues
#include <clues/syscalls/fs.hxx>

namespace clues {

void FcntlSystemCall::clear() {
	m_pars.clear();

	/* args */
	dup_num.reset();
	fd_flags_arg.reset();
	status_flags_arg.reset();

	/* retvals */
	result.reset();
	dupfd.reset();
	ret_fd_flags.reset();
	ret_status_flags.reset();
}

bool FcntlSystemCall::newSystemCall() {
	auto setDefaultParameters = [this]() {
		setParameters(fd, operation);
	};
	auto setNewParameters = [this, setDefaultParameters](auto &extra_par) {
		setDefaultParameters();
		setParameters(extra_par);
	};
	auto setDefaultReturnValue = [this]() {
		result.emplace(item::SuccessResult{});
		setReturnItem(*result);
	};

	clear();

	using Oper = item::FcntlOperation::Oper;
	switch (operation.operation()) {
		case Oper::DUPFD: /* fallthrough */
		case Oper::DUPFD_CLOEXEC: {
			dup_num.emplace(item::FileDescriptor{ItemType::PARAM_IN, item::AtSemantics{false},
				"lowest_fd", "lowest dup file descriptor number"});
			dupfd.emplace(item::FileDescriptor{ItemType::RETVAL, item::AtSemantics{false},
				"dupfd", "duplicated file descriptor"});
			setReturnItem(*dupfd);
			setNewParameters(*dup_num);
			break;
		} case Oper::GETFD: {
			setDefaultParameters();
			ret_fd_flags.emplace(item::FileDescFlagsValue{ItemType::RETVAL});
			setReturnItem(*ret_fd_flags);
			break;
		} case Oper::SETFD: {
			fd_flags_arg.emplace(item::FileDescFlagsValue{ItemType::PARAM_IN});
			setNewParameters(*fd_flags_arg);
			setDefaultReturnValue();
			break;
		} case Oper::GETFL: {
			ret_status_flags.emplace(item::OpenFlagsValue{ItemType::RETVAL});
			setParameters(fd, operation);
			setReturnItem(*ret_status_flags);
			break;
		} case Oper::SETFL: {
			status_flags_arg.emplace(item::OpenFlagsValue{ItemType::PARAM_IN});
			setNewParameters(*status_flags_arg);
			setDefaultReturnValue();
			break;
		} case Oper::SETLK: /* fallthrough */
		  case Oper::SETLKW: /* fallthrough */
		  case Oper::GETLK: {
			flock_arg.emplace(item::FLockParameter{});
			setNewParameters(*flock_arg);
			setDefaultReturnValue();
			break;
		} default: {
			setDefaultParameters();
			setDefaultReturnValue();
			break;
		}
	}

	return true;
}

} // end ns
