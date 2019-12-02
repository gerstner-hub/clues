#ifndef TUXTRACE_USAGEERROR_HXX
#define TUXTRACE_USAGEERROR_HXX

// tuxtrace
#include <tuxtrace/include/TuxTraceError.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	Exception type for when C library APIs fail
 **/
class UsageError :
	public TuxTraceError
{
public: // functions

	UsageError(const char *msg) :
		TuxTraceError("UsageError")
	{}
		
	void raise() override { throw *this; }

protected: // functions

	void generateMsg() const override { m_msg += m_error_msg; }

protected: // data

	std::string m_error_msg;
};

} // end ns

#endif // inc. guard

