#pragma once

#include <cosmos/compiler.hxx>

#include <clues/private/kernel/time.hxx>

#include <time.h>

/*
 * the struct timespec used with regular system calls, except for special
 * TIME64 variants (on I386).
 */
#ifdef COSMOS_I386
using canon_timespec = clues::timespec32;
using canon_timeval = clues::timeval32;
#else
using canon_timespec = struct timespec;
using canon_timeval = struct timeval;
#endif
