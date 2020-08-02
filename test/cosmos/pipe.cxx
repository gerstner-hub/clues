// C++
#include <string>
#include <iostream>

// Cosmos
#include "cosmos/io/Pipe.hxx"
#include "cosmos/io/StreamAdaptor.hxx"
#include "cosmos/proc/SubProc.hxx"
#include "cosmos/Init.hxx"

int main()
{
	clues::Init init;
	clues::Pipe pip;
	clues::OutputStreamAdaptor pip_out(pip);
	clues::InputStreamAdaptor pip_in(pip);

	pip_out << "test" << std::flush;
	pip_out.close();
	std::string s;
	pip_in >> s;

	if( s != "test" )
	{
		std::cerr << "Didn't get exact copy back from pipe!\n" << std::endl;
		std::cerr << "Got '" << s << "' instead\n" << std::endl;
		return 1;
	}

	std::cout << "successfully transmitted test data over pipe" << std::endl;

	return 0;
}

