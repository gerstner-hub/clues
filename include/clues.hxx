#pragma once

// clues
#include <clues/dso_export.h>

namespace cosmos {

class ILogger;

} // end ns

namespace clues {

/// Global logger instance to use for Clues library logging - if any
extern cosmos::ILogger *logger;

/// Configure a cosmos ILogger instance to use in the Clues library.
/**
 * The Clues library supports basic logging using the cosmos::ILogger
 * interface. By default no logger is configured.
 **/
void CLUES_API set_logger(cosmos::ILogger &);

} // end ns
