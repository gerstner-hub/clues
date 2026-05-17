// clues
#include <clues/items/other.hxx>
#include <clues/private/utils.hxx>

namespace clues::item {

std::string GetRandomFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(GRND_RANDOM);
	BITFLAGS_ADD(GRND_NONBLOCK);

	return BITFLAGS_STR();
}

void GetRandomFlagsValue::processValue(const Tracee&) {
	m_flags = cosmos::GetRandomFlags{valueAs<int>()};
}

} // end ns
