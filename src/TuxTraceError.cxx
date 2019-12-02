// C++
#include <sstream>

// tuxtrace
#include <tuxtrace/include/TuxTraceError.hxx>

namespace tuxtrace
{

const char* TuxTraceError::what() const throw()
{
	if( !m_msg.empty() )
		return m_msg.c_str();

	std::stringstream ss;
	ss << m_file << ":" << m_line
		<< " [" << m_func << "]: " << m_eclass << " occured.";

	m_msg = ss.str();

	generateMsg();

	return m_msg.c_str();
}

} // end ns


