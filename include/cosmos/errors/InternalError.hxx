#ifndef COSMOS_INTERNALERROR_HXX
#define COSMOS_INTERNALERROR_HXX

// cosmos
#include "cosmos/errors/CluesError.hxx"

namespace cosmos
{

/**
 * \brief
 * 	Exception type for grave internal errors
 * \details
 * 	To be used in case e.g. elemental preconditions that are considered a
 * 	given are not fulfilled.
 **/
class InternalError :
	public CluesError
{
public: // functions

	explicit InternalError(const char *msg) :
		CluesError("InternalError"),
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

