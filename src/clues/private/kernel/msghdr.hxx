#pragma once

// clues
#include <clues/private/kernel/types.hxx>

namespace clues {

extern "C" {

struct msghdr32 {
	compat_uptr_t msg_name;
	int msg_namelen;
	compat_uptr_t msg_iov;
	compat_size_t msg_iovlen;
	compat_uptr_t msg_control;
	compat_size_t msg_controllen;
	int msg_flags;
};

struct cmsghdr32 {
	compat_size_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};

} // end extern

} // end ns
