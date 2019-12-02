// C++
#include <iostream>

// tuxtrace
#include <tuxtrace/include/WaitRes.hxx>

std::ostream& operator<<(std::ostream &o, const tuxtrace::WaitRes &res)
{
	o << "Stopped: " << res.stopped() << "\n";
	o << "Exited: " << res.exited() << "\n";
	if( res.exited() )
		o << "Status: " << res.exitStatus() << "\n";

	return o;
}

