#pragma once

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/net.hxx>
#include <clues/utils.hxx>

/**
 * @file enum-specific format helpers. These helpers should only we included
 * where they are actually needed to avoid an explosion of the dependency
 * graph, due to the many nested enum types needed here..
 **/

namespace clues::format {

/*
 * the following are helpers for template programming to obtain a label for
 * enum types.
 */

inline std::string enumeration(const cosmos::SignalNr nr) {
	return format::signal(nr);
}

inline std::string enumeration(const ForeignPtr ptr) {
	return format::pointer(ptr);
}

inline std::string enumeration(const item::SocketDomain::Domain domain) {
	return std::string{item::SocketDomain::label(domain)};
}

inline std::string enumeration(const cosmos::Errno err) {
	return get_errno_label(err);
}

/// Tells us whether format::enumeration() exists for type T.
template <typename T>
constexpr bool has_enum_formatter = requires(T t) {
	enumeration(t);
};

} // end ns
