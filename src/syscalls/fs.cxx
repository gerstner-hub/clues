// cosmos
#include "types.hxx"
#include <cosmos/compiler.hxx>

// clues
#include <clues/logger.hxx>
#include <clues/syscalls/fs.hxx>
#include <clues/Tracee.hxx>

namespace clues {

void FcntlSystemCall::prepareNewSystemCall() {
	/* drop all but the fixed initial two parameters */
	dropParameters(2);

	// setup the default return value
	result.emplace();
	setReturnItem(*result);

	/* args */
	dup_lowest.reset();
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

bool FcntlSystemCall::check2ndPass(const Tracee &) {
	auto setExtraParameter = [this](auto &extra_par) {
		addParameters(extra_par);
	};
	auto setNewReturnItem = [this](auto &new_ret) {
		result.reset();
		setReturnItem(new_ret);
	};

	using Oper = item::FcntlOperation::Oper;
	switch (operation.operation()) {
		case Oper::DUPFD: [[fallthrough]];
		case Oper::DUPFD_CLOEXEC: {
			dup_lowest.emplace(
					ItemCfg{
						.label = "lowest_fd",
						.desc = "lowest dup file descriptor number"},
					item::AtSemantics{false});
			ret_dupfd.emplace(ItemCfg{
						.type = ItemType::RETVAL,
						.label = "dupfd",
						.desc = "duplicated file descriptor"},
					item::AtSemantics{false});
			setNewReturnItem(*ret_dupfd);
			setExtraParameter(*dup_lowest);
			break;
		} case Oper::GETFD: {
			ret_fd_flags.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_fd_flags);
			break;
		} case Oper::SETFD: {
			fd_flags_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*fd_flags_arg);
			break;
		} case Oper::GETFL: {
			ret_status_flags.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_status_flags);
			break;
		} case Oper::SETFL: {
			status_flags_arg.emplace(ItemType::PARAM_IN);
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
			flock_arg.emplace();
			setExtraParameter(*flock_arg);
			break;
		} case Oper::GETOWN: {
			ret_owner.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_owner);
			break;
		} case Oper::SETOWN: {
			owner_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*owner_arg);
			break;
		} case Oper::GETOWN_EX: {
			ext_owner_arg.emplace(ItemType::PARAM_OUT);
			setExtraParameter(*ext_owner_arg);
			break;
		} case Oper::SETOWN_EX: {
			ext_owner_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*ext_owner_arg);
			break;
		} case Oper::GETSIG: {
			ret_io_signal.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_io_signal);
			break;
		} case Oper::SETSIG: {
			io_signal_arg.emplace();
			setExtraParameter(*io_signal_arg);
			break;
		} case Oper::GETLEASE: {
			ret_lease.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_lease);
			break;
		} case Oper::SETLEASE: {
			lease_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*lease_arg);
			break;
		} case Oper::NOTIFY: {
			dnotify_arg.emplace();
			setExtraParameter(*dnotify_arg);
			break;
		} case Oper::SETPIPE_SZ: {
			pipe_size_arg.emplace(make_item_cfg("pipe size", "pipe buffer size"));
			setExtraParameter(*pipe_size_arg);
			/*
			 * SET and GET both return the current pipe size
			 */
			[[fallthrough]];
		} case Oper::GETPIPE_SZ: {
			ret_pipe_size.emplace(ItemCfg{ItemType::RETVAL, "pipe size", "pipe buffer size"});
			setNewReturnItem(*ret_pipe_size);
			break;
		} case Oper::ADD_SEALS: {
			file_seals_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*file_seals_arg);
			break;
		} case Oper::GET_SEALS: {
			ret_seals.emplace(ItemType::RETVAL);
			setNewReturnItem(*ret_seals);
			break;
		} case Oper::GET_RW_HINT: [[fallthrough]];
		  case Oper::GET_FILE_RW_HINT: {
			rw_hint_arg.emplace(ItemType::PARAM_OUT);
			setExtraParameter(*rw_hint_arg);
			break;
		} case Oper::SET_RW_HINT: [[fallthrough]];
		  case Oper::SET_FILE_RW_HINT: {
			rw_hint_arg.emplace(ItemType::PARAM_IN);
			setExtraParameter(*rw_hint_arg);
			break;
		} default: {
			/* unknown operation? keep defaults */
			break;
		}
	}

	return true;
}

void FcntlSystemCall::updateFDTracking(const Tracee &proc) {
	using enum item::FcntlOperation::Oper;

	if (cosmos::in_list(operation.operation(), {DUPFD, DUPFD_CLOEXEC})) {
		auto &info_map = proc.fdInfoMap();
		if (auto it = info_map.find(fd.fd()); it != info_map.end()) {
			auto info = it->second;
			info.fd = ret_dupfd->fd();
			trackFD(proc, std::move(info));
		} else {
			LOG_WARN("[" << cosmos::to_integral(proc.pid()) << "]"
					<< "Couldn't find dup source FD "
					<< cosmos::to_integral(fd.fd())
					<< " for tracking");
		}
	}
}

void OpenSystemCall::prepareNewSystemCall() {
	dropParameters(2);

	mode.reset();
}

bool OpenSystemCall::check2ndPass(const Tracee &) {
	using enum cosmos::OpenFlag;

	if (const auto _flags = flags.flags(); _flags[CREATE] || _flags[TMPFILE]) {
		mode.emplace();
		addParameters(*mode);
		return true;
	}

	return false;
}

void OpenSystemCall::updateFDTracking(const Tracee &proc) {
	FDInfo info{FDInfo::Type::FS_PATH, new_fd.fd()};
	info.path = filename.str();
	info.mode = flags.mode();
	info.flags = flags.flags();
	trackFD(proc, std::move(info));
}

void OpenAtSystemCall::prepareNewSystemCall() {
	dropParameters(3);
	mode.reset();
}

bool OpenAtSystemCall::check2ndPass(const Tracee &) {
	using enum cosmos::OpenFlag;

	if (const auto _flags = flags.flags(); _flags[CREATE] || _flags[TMPFILE]) {
		mode.emplace();
		addParameters(*mode);
		return true;
	}

	return false;
}

void OpenAtSystemCall::updateFDTracking(const Tracee &proc) {
	FDInfo info{FDInfo::Type::FS_PATH, new_fd.fd()};
	info.path = filename.str();
	info.mode = flags.mode();
	info.flags = flags.flags();
	trackFD(proc, std::move(info));
}

void CloseSystemCall::updateFDTracking(const Tracee &proc) {
	dropFD(proc, fd.fd());
}

FAdviseSystemCall::FAdviseSystemCall(const SystemCallNr nr) :
		SystemCall{nr},
		off_variant{std::monostate{}},
		size_variant{std::monostate{}} {
	setReturnItem(result);
	// the ordering of parameters depends on the ABI / Architecture.
#ifdef COSMOS_I386
	m_is_native_64 = false;
#else
	setupPars64();

#endif
}

void FAdviseSystemCall::setupPars64() {
	m_is_native_64 = true;
	auto &off = off_variant.emplace<0>(item::OffsetValue{make_item_cfg("offset",
				"start offset of the byte range")});
	auto &size = size_variant.emplace<0>(item::SizeValue{make_item_cfg("size",
				"size of the byte range")});
	setParameters(fd, off, size, advice);
}

void FAdviseSystemCall::prepareNewSystemCall() {
	switch (abi()) {
		case ABI::AARCH64: {
			// keep the fixed parameters from construction time
			return;
		} case ABI::X86_64: {
			// in case we switched between 32 bit / 64 bit,
			// reconstruct everything with 64 bit native parameters.
			if (!m_is_native_64) {
				setupPars64();
			}
			return;
		} case ABI::I386: {
			m_is_native_64 = false;
			using enum item::CombinedOffsetValue::Ordering;
			const auto size_is_64 = this->callNr() == SystemCallNr::FADVISE64_64;
			item::CombinedOffsetValue *size64 = nullptr;
			item::SizeValue *size32 = nullptr;

			if (size_is_64) {
				size64 = &size_variant.emplace<1>(
					item::CombinedOffsetValue{LOW_THEN_HIGH,
						ItemCfg{.desc = "size of the byte range"}});
			} else {
				size32 = &size_variant.emplace<0>(item::SizeValue{make_item_cfg("size",
							"size of the byte range")});
			}

			auto &offset64 = off_variant.emplace<1>(
				item::CombinedOffsetValue{LOW_THEN_HIGH,
						ItemCfg{.desc = "start offset of the byte range"}});

			if (size_is_64) {
				setParameters(fd, offset64.lowerPar(), offset64,
						size64->lowerPar(), *size64, advice);

			} else {
				setParameters(fd, offset64.lowerPar(), offset64,
						*size32, advice);
			}

			return;
		} default: {
			throw cosmos::RuntimeError{"unsupported ABI"};
		}
	}
}

off_t FAdviseSystemCall::offset() const {
	if (auto *off = std::get_if<item::OffsetValue>(&off_variant)) {
		return off->value();
	} else {
		return std::get<item::CombinedOffsetValue>(off_variant).value();
	}
}

off_t FAdviseSystemCall::size() const {
	if (auto *size = std::get_if<item::SizeValue>(&size_variant)) {
		return size->value();
	} else {
		return std::get<item::CombinedOffsetValue>(size_variant).value();
	}
}

void FStatFSSystemCall::prepareNewSystemCall() {
	if (callNr() == SystemCallNr::FSTATFS64) {
		if (!size) {
			size.emplace(make_item_cfg("size", "size of struct statfs64"));
			setParameters(fd, *size, buf);
		}
	} else {
		if (size.has_value()) {
			size.reset();
			setParameters(fd, buf);
		}
	}
}

void StatFSSystemCall::prepareNewSystemCall() {
	if (callNr() == SystemCallNr::STATFS64) {
		if (!size) {
			size.emplace(make_item_cfg("size", "size of struct statfs64"));
			setParameters(path, *size, buf);
		}
	} else {
		if (size.has_value()) {
			size.reset();
			setParameters(path, buf);
		}
	}
}

void DupSystemCall::updateFDTracking(const Tracee &proc) {
	const auto &fd_map = proc.fdInfoMap();
	auto info = fd_map.find(oldfd.fd());

	if (info == fd_map.end()) {
		LOG_WARN(std::format("[{}]: source fd {} not found for dup()",
			cosmos::to_integral(proc.pid()),
			cosmos::to_integral(oldfd.fd())));
		return;
	}

	auto new_entry = FDInfo{info->second};
	new_entry.fd = retfd.fd();
	trackFD(proc, std::move(new_entry));
}

} // end ns
