#pragma once

// C++
#include <vector>

// clues
#include <clues/syscalls/net.hxx>
#include <clues/syscalls/sockopt.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

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

	explicit SocketCallBase();

	bool check2ndPass(const Tracee &proc) override {
		if (args.valid()) {
			transferValues(proc);
		}

		return false;
	}

	void postSystemCall(const Tracee &) override;

	/// Transfer values from `args` into BASE class items.
	/**
	 * We abuse `check2ndPass()` to transfer the multiplexed system call
	 * parameters from `args` into the base class system call items. This
	 * allows us to treat the system call as if it was a regular
	 * non-multiplexed system call.
	 **/
	virtual void transferValues(const Tracee&) = 0;

	/// Base class items that need to be updated after system call exit.
	std::vector<SystemCallItem*> m_update_args;

public: // data

	item::SocketCallType call;
	item::SocketCallArgs args;
};

/// Implementation of socketcall(SYS_SOCKET, ...).
class SocketCall_Socket :
		public SocketCallBase<SocketSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_SocketPair :
		public SocketCallBase<SocketPairSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Bind :
		public SocketCallBase<BindSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Connect :
		public SocketCallBase<ConnectSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Listen :
		public SocketCallBase<ListenSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Accept :
		public SocketCallBase<AcceptSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Shutdown :
		public SocketCallBase<ShutdownSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_GetSockName :
		public SocketCallBase<GetSockNameSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_GetPeerName :
		public SocketCallBase<GetPeerNameSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Recv :
		public SocketCallBase<RecvSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_RecvFrom :
		public SocketCallBase<RecvFromSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_RecvMsg :
		public SocketCallBase<RecvMsgSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_RecvMMsg :
		public SocketCallBase<RecvMMsgSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_Send :
		public SocketCallBase<SendSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_SendTo :
		public SocketCallBase<SendToSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_SendMsg :
		public SocketCallBase<SendMsgSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

class SocketCall_SendMMsg :
		public SocketCallBase<SendMMsgSystemCall> {
protected: // functions

	void transferValues(const Tracee&) override;
};

/// Further base type for GetSockOptSystemCall() variants in socketcall() context.
/**
 * Due to the ioctl() nature of both socketcall() and
 * getsockopt()/setsockopt() we need to deal with additional complexities.
 * This base type implements the value transfer logic for arbitrary more
 * specialized GetSockOptSystemCall types.
 **/
template <typename BASE>
class SocketCallGetSockOptBase :
		public SocketCallBase<BASE> {
protected: // functions

	void transferValues(const Tracee &proc) override;
};

class SocketCall_GetBoolSockOpt :
		public SocketCallGetSockOptBase<GetBoolSockOptSystemCall> {
};

class SocketCall_UnknownSockOpt :
		public SocketCallGetSockOptBase<GetUnknownSockOptSystemCall> {
};

CLUES_DEFAULT_VISIBILITY_OFF;

SystemCallPtr create_socket_call_syscall(const Tracee &tracee, const SystemCallInfo &info);

} // end ns
