// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/format.hxx>
#include <clues/items/io.hxx>
#include <clues/Tracee.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

void PipeEnds::processValue(const Tracee &proc) {
	int ends[2];

	if (!proc.readStruct(asPtr(), ends)) {
		// probably bad userspace address or Tracee died
		reset();
		return;
	}

	m_read_end = cosmos::FileNum{ends[0]};
	m_write_end = cosmos::FileNum{ends[1]};
}

std::string PipeEnds::str() const {
	if (haveEnds()) {
		const auto ends_array = cosmos::sprintf("%d, %d",
				cosmos::to_integral(m_read_end),
				cosmos::to_integral(m_write_end));
		return clues::format::pointer(asPtr(), ends_array);
	} else {
		return clues::format::pointer(asPtr());
	}
}

std::string PipeFlags::str() const {
	if (!m_flags) {
		return "N/A";
	}
	const auto flags = *m_flags;
	BITFLAGS_FORMAT_START(flags);

#define O_NOTIFICATION_PIPE O_EXCL

	BITFLAGS_ADD(O_CLOEXEC);
	BITFLAGS_ADD(O_DIRECT);
	BITFLAGS_ADD(O_NONBLOCK);
	/*
	 * This notification pipe mechanism is a pretty weird communication
	 * mechanism towards the kernel which can be used to e.g. get
	 * information out keyring events. A bit of a misused pipe for
	 * netlink-like purposes.
	 *
	 * From the tracing POV all we could do is interpreting the messages
	 * exchanged on such a pipe, but it doesn't seem worth the effort,
	 * I've never seen it in production.
	 */
	BITFLAGS_ADD(O_NOTIFICATION_PIPE);

	return BITFLAGS_STR();
}

void PipeFlags::processValue(const Tracee &) {
	m_flags = Flags{valueAs<int>()};
}

} // end ns
