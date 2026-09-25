#pragma once

// C++
#include <optional>

// clues
#include <clues/dso_export.h>
#include <clues/items/net.hxx>
#include <clues/items/sockopt.hxx>
#include <clues/items/strings.hxx>
#include <clues/syscalls/net.hxx>
#include <clues/SystemCallDB.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

enum class SockOptType {
	GET,
	SET
};

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
			name{level, SockOptType::GET},
			optvalp{optval},
			optlen{ItemCfg{
				.label = "optlen",
				.desc = "in-out pointer for option length"}} {
		setReturnItem(res);
	}

	item::SocketFD sockfd;
	item::SockOptLevel level;
	item::SockOptName name;
	// pointer to the specialized type's optval item.
	SystemCallItem *optvalp = nullptr;
	item::PointerToScalarInOut<int> optlen;

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
			name{level, SockOptType::SET},
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

/// getsockopt() system call returning a `char*` string option.
/**
 * These types of getsockopt() calls return arbitrary string data.
 **/
struct GetStringSockOptSystemCall :
		public GetSockOptSystemCall {

	item::StringBuffer optval;

	explicit GetStringSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{ItemType::PARAM_OUT,
				"optval", "char*"}} {
		addPars();
	}
};

/// setsockopt() system call setting a `char*` string option.
/**
 * \see GetStringSockOptSystemCall
 **/
struct SetStringSockOptSystemCall :
		public SetSockOptSystemCall {

	item::StringBuffer optval;

	explicit SetStringSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			SetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{ItemType::PARAM_OUT,
				"optval", "const char*"}} {
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

/// Installs a BPF program on a socket.
/**
 * This type carries a specialized item::FilterProg item which ensures that
 * the `optlen` of the setsockopt() is sufficient to process a `struct
 * sock_fprog`.
 **/
struct AttachFilterSockOptSystemCall :
		public SetSockOptSystemCall {

	item::AttachFilterSockOpt optval;

	explicit AttachFilterSockOptSystemCall(
			const std::optional<SystemCallNr> nr  = {}) :
			SetSockOptSystemCall{&optval, nr},
			optval{optlen} {
		addPars();
	}
};

/// Returns a previously installed BPF program.
/**
 * This is the GET counterpart to AttachFilterSockOptSystemCall.
 **/
struct GetFilterSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GetFilterSocktOpt optval;

	explicit GetFilterSockOptSystemCall(
			const std::optional<SystemCallNr> nr  = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen} {
		addPars();
	}
};

/// Gets the `domain` of the socket as specified in the `socket()` system call.
struct GetDomainSockOptSystemCall :
		public GetSockOptSystemCall {

	item::GetSockOptVal<item::SocketDomain::Domain> optval;

	explicit GetDomainSockOptSystemCall(
			const std::optional<SystemCallNr> nr = {}) :
			GetSockOptSystemCall{&optval, nr},
			optval{optlen, ItemCfg{.label = "domain", .desc = "int*"}} {
		addPars();
	}
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
