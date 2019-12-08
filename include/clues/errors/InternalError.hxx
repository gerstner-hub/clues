#ifndef CLUES_INTERNALERROR_HXX
#define CLUES_INTERNALERROR_HXX

// clues
#include "clues/errors/CluesError.hxx"

namespace clues
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

