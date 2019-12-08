#ifndef TUXTRACE_TUXTRACEERROR_HXX
#define TUXTRACE_TUXTRACEERROR_HXX

// C++
#include <exception>
#include <string>

// throw the given Exception type after added contextual information from the
// callers location
#define tt_throw(e) (e.setInfo(__FILE__, __LINE__, __FUNCTION__).raise())

namespace tuxtrace
{

/**
 * \brief
 * 	Base class for TuxTrace exceptions
 * \details
 * 	This base class carries the file, line and function contextual
 * 	information from where it was thrown. Furthermore it stores a
 * 	dynamically allocated string with runtime information.
 *
 * 	The tt_throw macro allows to transparently throw any type derived from
 * 	this base class, all contextual information filled in.
 *
 * 	Each derived type must implement the raise() function to allow to
 * 	throw the correct specialized type even when only the base class type
 * 	is known. The generateMsg() function can be overwritten to update the
 * 	error message content at the time what() is called.
 **/
class TuxTraceError :
	std::exception
{
public: // functions

	explicit TuxTraceError(const char *error_class) :
		m_error_class(error_class) {}

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

	/**
	 * \brief
	 * 	Implementation of the std::exception interface
	 * \details
	 * 	Returns a completely formatted message describing this error
	 * 	instance. The returned string is only valid for the lifetime
	 * 	of this object.
	 **/
	const char* what() const throw() override;

	/**
	 * \brief
	 * 	throw the most specialized type of this object in the
	 * 	inheritance hierarchy.
	 **/
	virtual void raise() = 0;

protected: // functions

	/**
	 * \brief
	 * 	Append type specific error information to m_msg
	 * \details
	 * 	This function is called by this base class implementation when
	 * 	the m_msg string needs to be appended implementation specific
	 * 	information.
	 *
	 * 	When this function is called then m_msg will be empty.
	 **/
	virtual void generateMsg() const {};

protected: // data

	const char *m_error_class = nullptr;
	mutable std::string m_msg;
	const char *m_file = nullptr;
	const char *m_func = nullptr;
	size_t m_line = 0;
};

} // end ns

#endif // inc. guard

