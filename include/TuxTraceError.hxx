#ifndef TUXTRACE_TUXTRACEERROR_HXX
#define TUXTRACE_TUXTRACEERROR_HXX

#include <exception>

#define tt_throw(e) (e.setInfo(__FILE__, __LINE__, __FUNCTION__).raise())

namespace tuxtrace
{

/**
 * \brief
 * 	Exception type for when C library APIs fail
 **/
class TuxTraceError :
	std::exception
{
public: // functions

	TuxTraceError(const char *error_class) :
		m_eclass(error_class) {}

	TuxTraceError& setInfo(
		const char *file,
		const size_t line,
		const char *func)
	{
		m_line = line;
		m_file = file;
		m_func = func;

		return *this;
	}

	const char* what() const throw() override;

	virtual void raise() = 0;

protected: // functions

	virtual void generateMsg() const {};

protected: // data

	const char *m_eclass;
	mutable std::string m_msg;
	const char *m_file;
	const char *m_func;
	size_t m_line;
	int m_errno;
};

} // end ns

#endif // inc. guard

