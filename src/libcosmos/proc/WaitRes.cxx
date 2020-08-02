// C++
#include <iostream>

// cosmos
#include "cosmos/proc/WaitRes.hxx"

std::ostream& operator<<(std::ostream &o, const clues::WaitRes &res)
{
	o << "Stopped: " << res.stopped() << "\n";
	o << "Exited: " << res.exited() << "\n";
	if( res.exited() )
		o << "Status: " << res.exitStatus() << "\n";

	return o;
}

