// Clues
#include "cosmos/time/Clock.hxx"
#include "cosmos/errors/ApiError.hxx"

namespace clues
{

void Clock::now(TimeSpec &ts) const
{
	auto res = clock_gettime(rawType(), &ts);

	if( res != 0 )
	{
		clues_throw( ApiError() );
	}
}

} // end ns

