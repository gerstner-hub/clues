// C++
#include <sstream>

// clues
#include "clues/TuxTraceError.hxx"

namespace clues
{

const char* TuxTraceError::what() const throw()
{
	if( !m_msg.empty() )
		return m_msg.c_str();

	generateMsg();

	std::stringstream ss;
	ss << m_file << ":" << m_line
		<< " [" << m_func << "]: " << m_error_class << ": ";

	m_msg = ss.str() + m_msg;

	return m_msg.c_str();
}

} // end ns

