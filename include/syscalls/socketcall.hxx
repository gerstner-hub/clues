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

	explicit SocketCallBase() :
			BASE{SystemCallNr::SOCKETCALL},
			args{call} {
		for (auto par: this->m_pars) {
			if (par->needsUpdate() && !par->deferFill()) {
				m_update_args.push_back(par);
			}
		}

		for (auto par: this->m_pars) {
			if (par->needsUpdate() && par->deferFill()) {
				m_update_args.push_back(par);
			}
		}

		BASE::setParameters(call, args);
	}

	bool check2ndPass(const Tracee &proc) override {
		if (args.valid()) {
			transferValues(proc);
		}

		return false;
	}

	void postSystemCall(const Tracee &proc) override {
		for (auto arg: m_update_args) {
			arg->updateData(proc);
		}
	}

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
 *
 * This is currently shared for both getsockopt() and setsockopt() as there
 * are no conflicts between the two on this level.
 **/
template <typename BASE>
class SocketCallSockOptBase :
		public SocketCallBase<BASE> {
protected: // functions

	void transferValues(const Tracee &proc) override {
		const auto &vec = this->args.args();
		this->sockfd.fill(proc, Word{vec[0]});
		this->level.fill(proc, Word{vec[1]});
		this->name.fill(proc, Word{vec[2]});
		this->optlen.fill(proc, Word{vec[4]});

		/* respect DEFER_FILL */
		this->optval.fill(proc, Word{vec[3]});
	}
};

/*
 * for concrete implementations of GetSockOptSystemCall and
 * SetSockOptSystemCall the pattern is always the same, use macros to reduce
 * the amount of code needed here.
 */

#define DEF_SOCKETCALL_SET_SOCK_OPT(kind) class SocketCall_Set##kind : \
		public SocketCallSockOptBase<Set##kind##SystemCall> { \
}
#define DEF_SOCKETCALL_GET_SOCK_OPT(kind) class SocketCall_Get##kind : \
		public SocketCallSockOptBase<Get##kind##SystemCall> { \
}
#define DEF_SOCKETCALL_SOCK_OPT(kind) \
	DEF_SOCKETCALL_SET_SOCK_OPT(kind); \
	DEF_SOCKETCALL_GET_SOCK_OPT(kind)

DEF_SOCKETCALL_SOCK_OPT(BoolSockOpt);
DEF_SOCKETCALL_SOCK_OPT(IntSockOpt);
DEF_SOCKETCALL_SOCK_OPT(StringSockOpt);
DEF_SOCKETCALL_SOCK_OPT(UnknownSockOpt);
DEF_SOCKETCALL_GET_SOCK_OPT(FilterSockOpt);
DEF_SOCKETCALL_GET_SOCK_OPT(DomainSockOpt);
DEF_SOCKETCALL_GET_SOCK_OPT(ErrorSockOpt);

#undef DEF_SOCKETCALL_GET_SOCK_OPT
#undef DEF_SOCKETCALL_SET_SOCK_OPT
#undef DEF_SOCKETCALL_SOCK_OPT

class SocketCall_AttachFilterSockOpt :
		public SocketCallSockOptBase<AttachFilterSockOptSystemCall> {
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
