#include <clues/items/process.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

std::string WaitOptionsItem::str() const {
	BITFLAGS_FORMAT_START(m_options);
	BITFLAGS_ADD(WEXITED);
	BITFLAGS_ADD(WSTOPPED);
	BITFLAGS_ADD(WCONTINUED);
	BITFLAGS_ADD(WNOHANG);
	BITFLAGS_ADD(WNOWAIT);
	BITFLAGS_ADD(__WALL);
	BITFLAGS_ADD(__WCLONE);
	BITFLAGS_ADD(__WNOTHREAD);

	return BITFLAGS_STR();
}

} // end ns
