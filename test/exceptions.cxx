#include <errno.h>

#include <iostream>

#include "clues/errors/ApiError.hxx"
#include "clues/errors/UsageError.hxx"
#include "clues/Init.hxx"

int main()
{
	clues::Init init;
	errno = ENOENT;
	try
	{
		clues_throw( clues::ApiError() );
	}
	catch( const clues::CluesError &ce )
	{
		std::cerr << "Testing ApiError (ENOENT): " << ce.what() << std::endl;
	}

	try
	{
		clues_throw( clues::UsageError("testing is good") );
	}
	catch( const clues::CluesError &ce )
	{
		std::cerr << "Testing UsageError: " << ce.what() << std::endl;
	}

	return 0;
}
