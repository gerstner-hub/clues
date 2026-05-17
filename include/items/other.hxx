// cosmos
#include <cosmos/random.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// The flags passed to calls like open().
class CLUES_API GetRandomFlagsValue :
		public SystemCallItem {
public:
	explicit GetRandomFlagsValue() :
			SystemCallItem{ItemType::PARAM_IN, "flags", "random flags"} {
	}

	std::string str() const override;

	cosmos::GetRandomFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::GetRandomFlags m_flags;
};

} // end ns
