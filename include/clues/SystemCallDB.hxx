#ifndef CLUES_SYSTEMCALLDB_HXX
#define CLUES_SYSTEMCALLDB_HXX

// clues
#include "clues/SystemCall.hxx"

namespace clues
{

/**
 * \brief
 * 	Stores information about each system call nr. in form of
 * 	SystemCall objects
 * \details
 * 	This is a caching map object. It doesn't fill in all system calls at
 * 	once but fills in each system call as it comes up.
 **/
class SystemCallDB :
	protected std::map<SystemCallNr, SystemCall*>
{
public:

	~SystemCallDB();

	SystemCall& get(const SystemCallNr nr);

	const SystemCall& get(const SystemCallNr nr) const
	{ return const_cast<SystemCallDB&>(*this).get(nr); }

protected:

	SystemCall* createSysCall(const SystemCallNr nr);
};

} // end ns

#endif // inc. guard

