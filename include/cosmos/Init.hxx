#ifndef COSMOS_INIT_HXX
#define COSMOS_INIT_HXX

namespace cosmos
{

/**
 * \brief
 * 	Initializes the cosmos library before first use
 * \details
 * 	The initialization of the library is required before any other
 * 	functionality of libcosmos is accessed.
 *
 * 	Multiple initializations can be performed but finishLibcosmos() needs
 * 	to be called the same number of times for cleanup to occur.
 **/
void initLibClues();

void finishLibClues();

/**
 * \brief
 * 	Convenience initialization object
 * \details
 * 	During the lifetime of this object the cosmos library remains
 * 	initialized.
 **/
class Init
{
public:
	Init() { initLibClues(); }

	~Init() { finishLibClues(); }
};

} // end ns

#endif // inc. guard

