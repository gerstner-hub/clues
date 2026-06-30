#pragma once

namespace clues {

extern "C" {

constexpr size_t OLD_UTS_LEN = 8;

struct oldold_utsname {
        char sysname[OLD_UTS_LEN + 1];
        char nodename[OLD_UTS_LEN + 1];
        char release[OLD_UTS_LEN + 1];
        char version[OLD_UTS_LEN + 1];
        char machine[OLD_UTS_LEN + 1];
};

constexpr size_t NEW_UTS_LEN = 64;

struct old_utsname {
        char sysname[NEW_UTS_LEN + 1];
        char nodename[NEW_UTS_LEN + 1];
        char release[NEW_UTS_LEN + 1];
        char version[NEW_UTS_LEN + 1];
        char machine[NEW_UTS_LEN + 1];
};

struct new_utsname {
        char sysname[NEW_UTS_LEN + 1];
        char nodename[NEW_UTS_LEN + 1];
        char release[NEW_UTS_LEN + 1];
        char version[NEW_UTS_LEN + 1];
        char machine[NEW_UTS_LEN + 1];
        char domainname[NEW_UTS_LEN + 1];
};

} // end extern

} // end ns
