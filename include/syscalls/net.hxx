#pragma once

// clues
#include <clues/items/fs.hxx>
#include <clues/items/net.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

struct SocketSystemCall :
		public SystemCall {

	explicit SocketSystemCall() :
			SystemCall{SystemCallNr::SOCKET},
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

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
