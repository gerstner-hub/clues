// clues
#include <clues/syscalls/fs.hxx>

namespace clues {

bool FcntlSystemCall::newSystemCall() {
	using Oper = item::FcntlOperation::Oper;

	m_pars.clear();

	dup_num.reset();
	flags_arg.reset();

	result.reset();
	dupfd.reset();
	ret_flags.reset();

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
		}
		case Oper::GETFD: {
			setParameters(fd, operation);
			ret_flags.emplace(item::FileDescFlagsValue{ItemType::PARAM_OUT});
			setReturnItem(*ret_flags);
			break;
		}
		case Oper::SETFD: {
			flags_arg.emplace(item::FileDescFlagsValue{ItemType::PARAM_IN});
			setParameters(fd, operation, *flags_arg);
			result.emplace(item::SuccessResult{});
			setReturnItem(*result);
			break;
		}
		default: {
			result.emplace(item::SuccessResult{});
			setReturnItem(*result);
			break;
		}
	}

	return true;
}

} // end ns
