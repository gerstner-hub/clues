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
	using Oper = item::FcntlOperation::Oper;

	clear();

	switch (operation.operation()) {
		case Oper::DUPFD: /* fallthrough */
		case Oper::DUPFD_CLOEXEC: {
			dup_num.emplace(item::FileDescriptor{ItemType::PARAM_IN, item::AtSemantics{false},
				"lowest_fd", "lowest dup file descriptor number"});
			dupfd.emplace(item::FileDescriptor{ItemType::PARAM_OUT, item::AtSemantics{false},
				"dupfd", "duplicated file descriptor"});
			setReturnItem(*dupfd);
			setParameters(fd, operation, *dup_num);
			break;
		} case Oper::GETFD: {
			setParameters(fd, operation);
			ret_fd_flags.emplace(item::FileDescFlagsValue{ItemType::PARAM_OUT});
			setReturnItem(*ret_fd_flags);
			break;
		} case Oper::SETFD: {
			fd_flags_arg.emplace(item::FileDescFlagsValue{ItemType::PARAM_IN});
			setParameters(fd, operation, *fd_flags_arg);
			result.emplace(item::SuccessResult{});
			setReturnItem(*result);
			break;
		} case Oper::GETFL: {
			ret_status_flags.emplace(item::OpenFlagsValue{ItemType::PARAM_OUT});
			setParameters(fd, operation);
			setReturnItem(*ret_status_flags);
			break;
		} case Oper::SETFL: {
			status_flags_arg.emplace(item::OpenFlagsValue{ItemType::PARAM_IN});
			setParameters(fd, operation, *status_flags_arg);
			result.emplace(item::SuccessResult{});
			setReturnItem(*result);
			break;
		} default: {
			setParameters(fd, operation);
			result.emplace(item::SuccessResult{});
			setReturnItem(*result);
			break;
		}
	}

	return true;
}

} // end ns
