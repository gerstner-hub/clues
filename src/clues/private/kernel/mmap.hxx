#pragma once

namespace clues {

extern "C" {

/// Old mmap() parameter on 32-bit ABIs like I386.
struct mmap_arg_struct {
        uint32_t addr;
        uint32_t len;
        uint32_t prot;
        uint32_t flags;
        uint32_t fd;
        uint32_t offset;
};

} // end extern

} // end ns
