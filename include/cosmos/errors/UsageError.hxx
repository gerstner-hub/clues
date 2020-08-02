#ifndef COSMOS_USAGEERROR_HXX
#define COSMOS_USAGEERROR_HXX

// cosmos
#include "cosmos/errors/CluesError.hxx"

namespace clues
{

/**
 * \brief
 * 	Exception type for logical usage errors within the application
 **/
class UsageError :
	public CluesError
{
public: // functions

	explicit UsageError(const char *msg) :
		CluesError("UsageError"),
		m_error_msg(msg)
	{}

	explicit UsageError(const std::string &msg) :
		UsageError(msg.c_str())
	{}

	void raise() override { throw *this; }

protected: // functions

	void generateMsg() const override { m_msg += m_error_msg; }

protected: // data

	std::string m_error_msg;
};

} // end ns

#endif // inc. guard

