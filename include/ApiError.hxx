#ifndef TUXTRACE_APIERROR_HXX
#define TUXTRACE_APIERROR_HXX

// tuxtrace
#include <tuxtrace/include/TuxTraceError.hxx>

namespace tuxtrace
{

/**
 * \brief
 * 	Exception type for when C library APIs fail
 **/
class ApiError :
	public TuxTraceError
{
public: // functions

	ApiError(const int p_errno = 0);

	void raise() override { throw *this; }

	static std::string msg(int no);

protected: // functions

	void generateMsg() const override;

protected: // data

	int m_errno;
};

} // end ns

#endif // inc. guard

