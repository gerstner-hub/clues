#include <errno.h>

#include <iostream>

#include "clues/ApiError.hxx"
#include "clues/UsageError.hxx"

int main()
{
	errno = ENOENT;
	try
	{
		clues_throw( tuxtrace::ApiError() );
	}
	catch( const tuxtrace::TuxTraceError &tte )
	{
		std::cerr << "Testing ApiError (ENOENT): " << tte.what() << std::endl;
	}

	try
	{
		clues_throw( tuxtrace::UsageError("testing is good") );
	}
	catch( const tuxtrace::TuxTraceError &tte )
	{
		std::cerr << "Testing UsageError: " << tte.what() << std::endl;
	}

	return 0;
}
