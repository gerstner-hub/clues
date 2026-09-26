#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/error/errno.hxx>

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

#define DEF_GET_SOCK_OPT_TYPE_FULL(_name, _item, _cfg) \
	struct _name##SockOptSystemCall : \
		public GetSockOptSystemCall { \
	\
	_item optval; \
	\
	explicit _name##SockOptSystemCall( \
			const std::optional<SystemCallNr> nr = {}) : \
			GetSockOptSystemCall{&optval, nr}, \
			optval{optlen, _cfg} { \
		addPars(); \
	} \
}

#define DEF_GET_SOCK_OPT_TYPE(_name, _item, _cfg) \
	DEF_GET_SOCK_OPT_TYPE_FULL(Get##_name, _item, _cfg)

#define DEF_SET_SOCK_OPT_TYPE_FULL(_name, _item, _cfg) \
	struct _name##SockOptSystemCall : \
		public SetSockOptSystemCall { \
	\
	_item optval; \
	\
	explicit _name##SockOptSystemCall( \
			const std::optional<SystemCallNr> nr = {}) : \
			SetSockOptSystemCall{&optval, nr}, \
			optval{optlen, _cfg} { \
		addPars(); \
	} \
}

#define DEF_SET_SOCK_OPT_TYPE(_name, _item, _cfg) \
	DEF_SET_SOCK_OPT_TYPE_FULL(Set##_name, _item, _cfg)

/// GetBoolSockOptSystemCall returning a boolean option.
/**
 * For simplicity we're using a GetSockOptVal<int> here, since technically the
 * type of the pointed-to variable still is an `int`. Semantically the kernel
 * usually accepts any value > 0 to be interpreted as `true`.
 *
 * On libclues level it is helpful to explicitly model boolean options which
 * can be clearly evaluated contrary to arbitrary integer options.
 **/
DEF_GET_SOCK_OPT_TYPE(Bool,
		item::GetSockOptVal<int>,
		ItemCfg{.desc = "int* (boolean)"});


/// SetBoolSockOptSystemCall modifying a boolean option.
/**
 * \see GetBoolSockOptSystemCall
 **/
DEF_SET_SOCK_OPT_TYPE(Bool,
		item::SetSockOptVal<int>,
		ItemCfg{.desc = "int* (boolean)"});

/// GetIntSockOptSystemCall returning an `int` option.
/**
 * These types of getsockopt() calls return arbitrary integer values. This is
 * the default type used for socket options if not documented otherwise.
 **/
DEF_GET_SOCK_OPT_TYPE(Int,
		item::GetSockOptVal<int>,
		ItemCfg{.desc = "int*"});

/// SetIntSockOptSystemCall modifying an integer option.
/**
 * \see GetIntSockOptSystemCall
 **/
DEF_SET_SOCK_OPT_TYPE(Int,
		item::SetSockOptVal<int>,
		ItemCfg{.desc = "int*"});

/// GetStringSockOptSystemCall returning a `char*` string option.
/**
 * These types of getsockopt() calls return arbitrary string data.
 **/
DEF_GET_SOCK_OPT_TYPE(String,
		item::StringBuffer,
		ItemCfg(ItemType::PARAM_OUT, "optval", "char*"));

/// SetStringSockOptSystemCall setting a `char*` string option.
/**
 * \see GetStringSockOptSystemCall
 **/
DEF_SET_SOCK_OPT_TYPE(String,
		item::StringBuffer,
		ItemCfg(ItemType::PARAM_OUT, "optval", "const char*"));

/// AttachFilterSockOptSystemCall installs a BPF program on a socket.
/**
 * This type carries a specialized item::FilterProg item which ensures that
 * the `optlen` of the setsockopt() is sufficient to process a `struct
 * sock_fprog`.
 **/
DEF_SET_SOCK_OPT_TYPE_FULL(AttachFilter, item::AttachFilterSockOpt,);

/// GetFilterSockOptSystemCall ~eturns a previously installed BPF program.
/**
 * This is the GET counterpart to AttachFilterSockOptSystemCall.
 **/
DEF_GET_SOCK_OPT_TYPE(Filter, item::GetFilterSocktOpt,);

/// GetDomainSockOptSystemCall gets the `domain` of the socket.
/**
 * This is the value specified in the `socket()` system call during socket
 * creation.
 **/
DEF_GET_SOCK_OPT_TYPE(Domain,
		item::GetSockOptVal<item::SocketDomain::Domain>,
		ItemCfg({}, "domain", "int*"));

/// GetErrorSockOptSystemCall returns any pending socket error as an errno.
/**
 * If no error is pending then Errno::SUCCESS is returned by the kernel.
 **/
DEF_GET_SOCK_OPT_TYPE(Error,
		item::GetSockOptVal<cosmos::Errno>,
		ItemCfg({}, "errno", "int*"));

/// GetLingerSockOptSystemCall returns the currently set `struct linger`.
DEF_GET_SOCK_OPT_TYPE(Linger,
		item::GetLingerSockOpt, );

/// SetLingerSockOptSystemCall sets a new `struct linger`.
DEF_SET_SOCK_OPT_TYPE(Linger,
		item::SetLingerSockOpt, );

#undef DEF_GET_SOCK_OPT_TYPE
#undef DEF_GET_SOCK_OPT_TYPE_FULL
#undef DEF_SET_SOCK_OPT_TYPE
#undef DEF_SET_SOCK_OPT_TYPE_FULL

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

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
