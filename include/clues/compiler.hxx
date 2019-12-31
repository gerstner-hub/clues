#include <iosfwd>

#if defined(__GLIBCXX__)
#       define CLUES_GNU_CXXLIB
#elif defined(_LIBCPP_VERSION)
#       define CLUES_LLVM_CXXLIB
#else
#       error "Couldn't determine the kind of C++ standard library"
#endif
