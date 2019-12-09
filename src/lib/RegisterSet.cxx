// C++
#include <iostream>

// Clues
#include "clues/RegisterSet.hxx"

namespace clues
{
} // end ns

std::ostream& operator<<(std::ostream &o, const clues::RegisterSet &rs)
{
	for( size_t i = 0; i < rs.numRegisters(); i++ )
	{
		if( i )
			o << "\n";
		o << clues::getRegisterName(i) << " = " << rs.registerValue(i);
	}

	return o;
}

