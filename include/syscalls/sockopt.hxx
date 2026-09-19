#pragma once

// clues
#include <clues/dso_export.h>
#include <clues/items/net.hxx>
#include <clues/syscalls/net.hxx>
#include <clues/SystemCallDB.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

/// Base class for getsockopt() system call variants.
/**
 * getsockopt() is an ioctl-style system call, thus we need many more
 * specialized types to model the concrete system call arguments expected for
 * combinations of option level and option name. This is a base class for all
 * these types.
 **/
struct GetSockOptSystemCall :
		public SystemCall {

	explicit GetSockOptSystemCall(
			SystemCallItem *optval,
			const SystemCallNr nr = SystemCallNr::GETSOCKOPT) :
			SystemCall{nr},
			name{level},
			optvalp{optval},
			optlen{ItemCfg{.label = "optlen", .desc = "out pointer to option length"}} {
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::SockOptLevel level;
	item::SockOptName name;
	// pointer to the specialized type's optval item.
	SystemCallItem *optvalp = nullptr;
	item::PointerToScalar<int> optlen;

	item::SuccessResult res;

protected: // functions

	/// Register the call's parameters.
	/**
	 * This *must* be called by specializations after the full system call
	 * class hierarchy including the concerete `optval` has been
	 * constructed.
	 **/
	void addPars() {
		/*
		 * we need to do this outside the constructor, since `optvalp`
		 * refers to a member in a more specialized type, so we cannot
		 * modify it until it's been properly constructed.
		 */
		addParameters(sockfd, level, name, *optvalp, optlen);
	}
};

struct GetBoolSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GetSockOptVal<int> optval;

	explicit GetBoolSockOptSystemCall(const SystemCallNr nr = SystemCallNr::GETSOCKOPT) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.desc = "int* (boolean)"}} {
		addPars();
	}
};

struct GetUnknownSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GenericPointerValue optval;

	explicit GetUnknownSockOptSystemCall(const SystemCallNr nr = SystemCallNr::GETSOCKOPT) :
			GetSockOptSystemCall{&optval, nr},
			optval{ItemCfg{.label = "optval", .desc = "unknown option data"}} {
		addPars();
	}
};

CLUES_DEFAULT_VISIBILITY_OFF;

SystemCallPtr create_getsockopt_syscall(const Tracee &, const SystemCallInfo &info);

} // end ns
