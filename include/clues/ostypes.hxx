#ifndef CLUES_OSTYPES_HXX
#define CLUES_OSTYPES_HXX

// Linux
#include <unistd.h>

namespace clues
{

/*
 * these are not part of the SubProc class, because then we'd get mutual
 * dependencies between Signal and SubProc headers.
 */
typedef pid_t ProcessID;
constexpr pid_t INVALID_PID = -1;

} // end ns

#endif // inc. agurd

