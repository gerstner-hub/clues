// C++
#include <string>
#include <iostream>

// Clues
#include "clues/Pipe.hxx"
#include "clues/StreamAdaptor.hxx"
#include "clues/SubProc.hxx"

int main()
{
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

