#ifndef CLUES_PROCESS_HXX
#define CLUES_PROCESS_HXX

// Clues
#include "clues/ostypes.hxx"

namespace clues
{

/**
 * \brief
 *	Various process related functionality
 **/
class Process
{
public: // functions

	explicit Process() {}

	/**
	 * \brief
	 *	Returns the process ID of the current process
	 **/
	ProcessID getPid() const
	{
		return m_own_pid == INVALID_PID ?
			cachePid() : m_own_pid;
	}

	/**
	 * \brief
	 *	Returns the process ID of the parent of the current process
	 **/
	ProcessID getPPid() const
	{
		return m_parent_pid == INVALID_PID ?
			cachePPid() : m_parent_pid;
	}

protected: // functions

	ProcessID cachePid() const;

	ProcessID cachePPid() const;

protected: // data

	mutable ProcessID m_own_pid = INVALID_PID;
	mutable ProcessID m_parent_pid = INVALID_PID;
};

//! a central instance for quick access to process information
extern Process g_process;

}; // end ns

#endif // inc. guard

