#ifndef CLUES_USAGEERROR_HXX
#define CLUES_USAGEERROR_HXX

// clues
#include "clues/TuxTraceError.hxx"

namespace clues
{

/**
 * \brief
 * 	Exception type for logical usage errors within the application
 **/
class UsageError :
	public TuxTraceError
{
public: // functions

	explicit UsageError(const char *msg) :
		TuxTraceError("UsageError"),
		m_error_msg(msg)
	{}

	void raise() override { throw *this; }

protected: // functions

	void generateMsg() const override { m_msg += m_error_msg; }

protected: // data

	std::string m_error_msg;
};

} // end ns

#endif // inc. guard

