#include <clues/logger.hxx>

namespace clues {

cosmos::ILogger *logger = nullptr;

void set_logger(cosmos::ILogger &_logger) {
	logger = &_logger;
}

} // end ns
