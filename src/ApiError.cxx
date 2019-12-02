// C++
#include <sstream>
#include <cstring>

// Linux
#include <errno.h>

// tuxtrace
#include <tuxtrace/include/ApiError.hxx>

namespace tuxtrace
{

ApiError::ApiError(const int p_errno) :
	TuxTraceError("ApiError"),
	m_errno( p_errno == 0 ? errno : p_errno )
{}

void ApiError::generateMsg() const
{
	std::stringstream ss;

	ss << "\n" << msg(m_errno) << " (" << m_errno << ")";

	m_msg += ss.str();
}

std::string ApiError::msg(int no)
{
	std::string error;
	error.resize(512);

	const char *text = ::strerror_r( no, &error[0], error.size() );

	return text;
}

} // end ns

