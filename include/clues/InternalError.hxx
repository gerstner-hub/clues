#ifndef TUXTRACE_INTERNALERROR_HXX
#define TUXTRACE_INTERNALERROR_HXX

// clues
#include "clues/TuxTraceError.hxx"

namespace tuxtrace
{

/**
 * \brief
 * 	Exception type for grave internal errors
 * \details
 * 	To be used in case e.g. elemental preconditions that are considered a
 * 	given are not fulfilled.
 **/
class InternalError :
	public TuxTraceError
{
public: // functions

	explicit InternalError(const char *msg) :
		TuxTraceError("InternalError"),
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

