#include <errno.h>

#include <iostream>

// Cosmos
#include "cosmos/errors/ApiError.hxx"
#include "cosmos/errors/UsageError.hxx"
#include "cosmos/Init.hxx"

int main()
{
	cosmos::Init init;
	errno = ENOENT;
	try
	{
		clues_throw( cosmos::ApiError() );
	}
	catch( const cosmos::CluesError &ce )
	{
		std::cerr << "Testing ApiError (ENOENT): " << ce.what() << std::endl;
	}

	try
	{
		clues_throw( cosmos::UsageError("testing is good") );
	}
	catch( const cosmos::CluesError &ce )
	{
		std::cerr << "Testing UsageError: " << ce.what() << std::endl;
	}

	return 0;
}
