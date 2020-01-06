#ifndef CLUES_INIT_HXX
#define CLUES_INIT_HXX

namespace clues
{

/**
 * \brief
 * 	Initializes the clues library before first use
 * \details
 * 	The initialization of the library is required before any other
 * 	functionality of libclues is accessed.
 *
 * 	Multiple initializations can be performed but finishLibClues() needs
 * 	to be called the same number of times for cleanup to occur.
 **/
void initLibClues();

void finishLibClues();

/**
 * \brief
 * 	Convenience initialization object
 * \details
 * 	During the lifetime of this object the clues library remains
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

