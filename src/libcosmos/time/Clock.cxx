// Cosmos
#include "cosmos/time/Clock.hxx"
#include "cosmos/errors/ApiError.hxx"

namespace cosmos
{

void Clock::now(TimeSpec &ts) const
{
	auto res = clock_gettime(rawType(), &ts);

	if( res != 0 )
	{
		cosmos_throw( ApiError() );
	}
}

} // end ns

