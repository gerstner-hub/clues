#include <errno.h>

#include <iostream>

#include "tuxtrace/include/ApiError.hxx"
#include "tuxtrace/include/UsageError.hxx"

int main()
{
	errno = ENOENT;
	try
	{
		tt_throw( tuxtrace::ApiError() );
	}
	catch( const tuxtrace::TuxTraceError &tte )
	{
		std::cerr << "Testing ApiError (ENOENT): " << tte.what() << std::endl;
	}

	try
	{
		tt_throw( tuxtrace::UsageError("testing is good") );
	}
	catch( const tuxtrace::TuxTraceError &tte )
	{
		std::cerr << "Testing UsageError: " << tte.what() << std::endl;
	}

	return 0;
}
