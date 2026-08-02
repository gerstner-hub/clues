#pragma once

// C++
#include <vector>

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
			prot{domain},
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

struct SocketPairSystemCall :
		public SystemCall {

	explicit SocketPairSystemCall(const SystemCallNr nr = SystemCallNr::SOCKETPAIR) :
			SystemCall{nr},
			prot{domain} {
		setParameters(domain, type, prot, pair);
		setReturnItem(res);
	}

	item::SocketDomain domain;
	item::SocketType type;
	item::SocketProtocol prot;
	item::SocketPair pair;

	item::SuccessResult res;

protected: // functions

	void updateFDTracking(const Tracee &proc) override;
};

struct BindSystemCall :
		public SystemCall {

	explicit BindSystemCall(const SystemCallNr nr = SystemCallNr::BIND) :
			SystemCall{nr},
			addr{ItemCfg{.type = ItemType::PARAM_IN}, &addrlen} {
		addParameters(sockfd, addr, addrlen);
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::SocketAddress addr;
	item::AddressLength addrlen;

	item::SuccessResult res;
};

struct ConnectSystemCall :
		public SystemCall {

	explicit ConnectSystemCall(const SystemCallNr nr = SystemCallNr::CONNECT) :
			SystemCall{nr},
			addr{ItemCfg{.type = ItemType::PARAM_IN}, &addrlen} {
		addParameters(sockfd, addr, addrlen);
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::SocketAddress addr;
	item::AddressLength addrlen;

	item::SuccessResult res;
};

struct ListenSystemCall :
		public SystemCall {

	explicit ListenSystemCall(const SystemCallNr nr = SystemCallNr::LISTEN) :
			SystemCall{nr},
       			backlog{ItemCfg{.label = "backlog"}} {
		addParameters(sockfd, backlog);
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::IntValue backlog;

	item::SuccessResult res;
};

/// Type used for accept() and accept4().
/**
 * This type is used for both accept() and accept4(). In the case of accept()
 * the `flags` item is always set to 0.
 **/
struct AcceptSystemCall :
		public SystemCall {

	explicit AcceptSystemCall(const SystemCallNr nr =
				SystemCallNr::ACCEPT) :
			SystemCall{nr},
			addr{ItemCfg{.type = ItemType::PARAM_OUT}, &addrlen},
			new_fd{ItemCfg{.type = ItemType::RETVAL}} {
		setParameters(sockfd, addr, addrlen);
		setReturnItem(new_fd);

		if (nr == SystemCallNr::ACCEPT4) {
			addParameters(flags);
		}
	}

	item::SocketFD sockfd;
	item::SocketAddress addr;
	item::AddressLengthPointer addrlen;
	item::AcceptFlags flags;

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

CLUES_DEFAULT_VISIBILITY_OFF;

SystemCallPtr create_socket_call_syscall(const SystemCallInfo &info);

} // end ns
