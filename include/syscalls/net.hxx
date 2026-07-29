#pragma once

// clues
#include <clues/items/fs.hxx>
#include <clues/items/net.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

struct SocketSystemCall :
		public SystemCall {

	explicit SocketSystemCall(const SystemCallNr nr = SystemCallNr::SOCKET) :
			SystemCall{nr},
			new_fd{ItemCfg{.type = ItemType::RETVAL}} {
		setParameters(domain, type, prot);
		setReturnItem(new_fd);
	}

	item::SocketDomain domain;
	item::SocketType type;
	item::SocketProtocol prot;

	item::FileDescriptor new_fd;

protected: // functions

	void updateFDTracking(const Tracee &proc) override;
};

/// Base class for `socketcall()` specializations.
/**
 * The socketcall() system call on legacy ABIs multiplexes all socket-related
 * system calls. This calls helps to facilitate reuse of code and to make this
 * ABI implementation detail transparent to users of libclues, if they don't
 * care about it.
 *
 * The concept is that SocketCallBase derives from the regular non-multiplexed
 * SystemCall type e.g. `SocketSystemCall` for `socketcall(SYS_SOCKET, ...)`.
 * This call will register the `call` and `args` parameters as is appropriate
 * for `socketcall()`. When parsing for system call entry is finished, the
 * data seen in `args` will be transfered into the base class system call
 * items via the virtual function call `transferValues()` which must be
 * implemented by each specialization of this type.
 **/
template <typename BASE>
class SocketCallBase :
		public BASE {

protected:

	explicit SocketCallBase() :
			BASE{SystemCallNr::SOCKETCALL},
			args{call} {
		BASE::setParameters(call, args);
	}

	bool check2ndPass(const Tracee &proc) override {
		transferValues(proc);
		return false;
	}

	/// Transfer values from `args` into BASE class items.
	/**
	 * We abuse `check2ndPass()` to transfer the multiplexed system call
	 * parameters from `args` into the base class system call items. This
	 * allows us to treat the system call as if it was a regular
	 * non-multiplexed system call.
	 **/
	virtual void transferValues(const Tracee&) = 0;

	item::SocketCallType call;
	item::SocketCallArgs args;
};

/// Implementation of socketcall(SYS_SOCKET, ...).
class SocketCall_Socket :
		public SocketCallBase<SocketSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

CLUES_DEFAULT_VISIBILITY_OFF;

SystemCallPtr create_socket_call_syscall(const SystemCallInfo &info);

} // end ns
