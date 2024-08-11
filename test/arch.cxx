// C++
#include <iostream>

// Cosmos
#include "cosmos/cosmos.hxx"

// Clues
#include "clues/RegisterSet.hxx"
#include "clues/Arch.hxx"

int main() {
	cosmos::Init init;
	std::cout << "is i386? " << clues::isi386() << "\n";
	std::cout << "is x86_64? " << clues::isx86_64() << "\n";
	std::cout << "num_syscall_regs: " << clues::SYSCALL_MAX_PARS << "\n";

	clues::RegisterSet rs(clues::RegisterSet::ZeroInit{true});
	std::cout << "RegisterSet: " << rs << std::endl;
	return 0;
}
