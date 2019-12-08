#include <errno.h>

#include <iostream>

#include "clues/ApiError.hxx"
#include "clues/UsageError.hxx"

int main()
{
	errno = ENOENT;
	try
	{
		clues_throw( clues::ApiError() );
	}
	catch( const clues::TuxTraceError &tte )
	{
		std::cerr << "Testing ApiError (ENOENT): " << tte.what() << std::endl;
	}

	try
	{
		clues_throw( clues::UsageError("testing is good") );
	}
	catch( const clues::TuxTraceError &tte )
	{
		std::cerr << "Testing UsageError: " << tte.what() << std::endl;
	}

	return 0;
}
