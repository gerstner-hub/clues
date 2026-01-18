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
	owner_arg.reset();
	ext_owner_arg.reset();
	io_signal_arg.reset();
	lease_arg.reset();
	dnotify_arg.reset();
	pipe_size_arg.reset();
	file_seals_arg.reset();
	rw_hint_arg.reset();

	/* retvals */
	ret_dupfd.reset();
	ret_fd_flags.reset();
	ret_status_flags.reset();
	ret_owner.reset();
	ret_io_signal.reset();
	ret_lease.reset();
	ret_pipe_size.reset();
	ret_seals.reset();
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
			ret_dupfd.emplace(item::FileDescriptor{ItemType::RETVAL, item::AtSemantics{false},
				"dupfd", "duplicated file descriptor"});
			setNewReturnItem(*ret_dupfd);
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
		  case Oper::SETLK64: [[fallthrough]];
		  case Oper::SETLKW64: [[fallthrough]];
		  case Oper::GETLK64: [[fallthrough]];
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
		} case Oper::GETOWN: {
			ret_owner.emplace(item::FileDescOwner{ItemType::RETVAL});
			setNewReturnItem(*ret_owner);
			break;
		} case Oper::SETOWN: {
			owner_arg.emplace(item::FileDescOwner{ItemType::PARAM_IN});
			setExtraParameter(*owner_arg);
			break;
		} case Oper::GETOWN_EX: {
			ext_owner_arg.emplace(item::ExtFileDescOwner{ItemType::PARAM_OUT});
			setExtraParameter(*ext_owner_arg);
			break;
		} case Oper::SETOWN_EX: {
			ext_owner_arg.emplace(item::ExtFileDescOwner{ItemType::PARAM_IN});
			setExtraParameter(*ext_owner_arg);
			break;
		} case Oper::GETSIG: {
			ret_io_signal.emplace(item::SignalNumber{ItemType::RETVAL});
			setNewReturnItem(*ret_io_signal);
			break;
		} case Oper::SETSIG: {
			io_signal_arg.emplace(item::SignalNumber{});
			setExtraParameter(*io_signal_arg);
			break;
		} case Oper::GETLEASE: {
			ret_lease.emplace(item::LeaseType{ItemType::RETVAL});
			setNewReturnItem(*ret_lease);
			break;
		} case Oper::SETLEASE: {
			lease_arg.emplace(item::LeaseType{ItemType::PARAM_IN});
			setExtraParameter(*lease_arg);
			break;
		} case Oper::NOTIFY: {
			dnotify_arg.emplace(item::DNotifySettings{});
			setExtraParameter(*dnotify_arg);
			break;
		} case Oper::SETPIPE_SZ: {
			pipe_size_arg.emplace(item::IntValue{"pipe size", "pipe buffer size"});
			setExtraParameter(*pipe_size_arg);
			/*
			 * SET and GET both return the current pipe size
			 */
			[[fallthrough]];
		} case Oper::GETPIPE_SZ: {
			ret_pipe_size.emplace(item::IntValue{"pipe size", "pipe buffer size", ItemType::RETVAL});
			setNewReturnItem(*ret_pipe_size);
			break;
		} case Oper::ADD_SEALS: {
			file_seals_arg.emplace(item::FileSealSettings{ItemType::PARAM_IN});
			setExtraParameter(*file_seals_arg);
			break;
		} case Oper::GET_SEALS: {
			ret_seals.emplace(item::FileSealSettings{ItemType::RETVAL});
			setNewReturnItem(*ret_seals);
			break;
		} case Oper::GET_RW_HINT: [[fallthrough]];
		  case Oper::GET_FILE_RW_HINT: {
			rw_hint_arg.emplace(item::ReadWriteHint{ItemType::PARAM_OUT});
			setExtraParameter(*rw_hint_arg);
			break;
		} case Oper::SET_RW_HINT: [[fallthrough]];
		  case Oper::SET_FILE_RW_HINT: {
			rw_hint_arg.emplace(item::ReadWriteHint{ItemType::PARAM_IN});
			setExtraParameter(*rw_hint_arg);
			break;
		} default: {
			/* unknown operation? keep defaults */
			break;
		}
	}

	return true;
}

} // end ns
