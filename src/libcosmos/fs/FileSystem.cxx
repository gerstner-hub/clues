// cosmos
#include "cosmos/fs/FileSystem.hxx"
#include "cosmos/errors/ApiError.hxx"

// Linux
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

namespace cosmos
{

bool FileSystem::existsFile(const std::string &path)
{
	struct stat s;
	if( lstat(path.c_str(), &s) == 0 )
		return true;
	else if( errno != ENOENT )
		cosmos_throw( ApiError() );

	return false;
}

} // end ns
