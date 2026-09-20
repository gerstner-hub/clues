#pragma once

// C++
#include <optional>

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
			const std::optional<SystemCallNr> nr = {}) :
			SystemCall{nr ? *nr : SystemCallNr::GETSOCKOPT},
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

/// getsockopt() system call returning a boolean option.
/**
 * For simplicity we're a GetSockOptVal<int> here, since technically the type
 * of the pointed-to variable still is an int. Semantically the kernel usually
 * accepts any value > 0 to be interpreted as `true`.
 *
 * On libclues level it is helpful to explicitly model boolean options which
 * can be clearly evaluated contrary to arbitrary integer options.
 **/
struct GetBoolSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GetSockOptVal<int> optval;

	explicit GetBoolSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.desc = "int* (boolean)"}} {
		addPars();
	}
};

/// getsockopt() system call returning an `int` option.
/**
 * These types of getsockopt() calls return arbitrary integer values. This is
 * the default type used for socket options if not documented otherwise.
 **/
struct GetIntSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GetSockOptVal<int> optval;

	explicit GetIntSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.desc = "int*"}} {
		addPars();
	}
};

/// Fallback type for getsockopt() system calls unknown to libclues.
/**
 * libclues uses this type in case invalid or not yet supported getsockopt()
 * level / name combinations appear. The `optval` is simply modeled as a
 * GenericPointerValue, whoose target will not be interpreted further.
 **/
struct GetUnknownSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GenericPointerValue optval;

	explicit GetUnknownSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{ItemCfg{.label = "optval", .desc = "unknown option data"}} {
		addPars();
	}
};

/// Base class for setsockopt() system call variants.
/**
 * This is very similar to GetSockOptSystemCall, but instead of a value-result
 * pointer for `optlen`, a pass-by-value integer is used. similary `optval` is
 * input data only and will not be written to by the kernel.
 *
 * \see GetSockOptSystemCall
 **/
struct SetSockOptSystemCall :
		public SystemCall {

	explicit SetSockOptSystemCall(
			SystemCallItem *optval,
			const std::optional<SystemCallNr> nr = {}) :
			SystemCall{nr ? *nr : SystemCallNr::SETSOCKOPT},
			name{level},
			optvalp{optval},
			optlen{ItemCfg{.label = "optlen", .desc = "size of optval in bytes"}} {
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::SockOptLevel level;
	item::SockOptName name;
	// pointer to the specialized type's optval item.
	SystemCallItem *optvalp = nullptr;
	// for getsockopt() this is passed by value, not as a pointer.
	item::IntValue optlen;

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

/// setsockopt() system call modifying a boolean option.
/**
 * \see GetBoolSockOptSystemCall
 **/
struct SetBoolSockOptSystemCall :
		public SetSockOptSystemCall {

	item::SetSockOptVal<int> optval;

	explicit SetBoolSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			SetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.desc = "int* (boolean)"}} {
		addPars();
	}
};

/// setsockopt() system call modifying an integer option.
/**
 * \see GetIntSockOptSystemCall
 **/
struct SetIntSockOptSystemCall :
		public SetSockOptSystemCall {

	item::SetSockOptVal<int> optval;

	explicit SetIntSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			SetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.desc = "int*"}} {
		addPars();
	}
};

/// Fallback type for setsockopt() system calls unknown to libclues.
/**
 * \see GetUnknownSockOptSystemCall
 **/
struct SetUnknownSockOptSystemCall :
		public SetSockOptSystemCall {

	item::GenericPointerValue optval;

	explicit SetUnknownSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			SetSockOptSystemCall{&optval, nr},
			optval{ItemCfg{.label = "optval", .desc = "unknown option data"}} {
		addPars();
	}
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
