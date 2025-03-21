// C++
#include <iostream>

// Cosmos
#include "cosmos/cosmos.hxx"

// Clues
#include "clues/RegisterSet.hxx"
#include "clues/arch.hxx"

int main() {
	cosmos::Init init;
	std::cout << "is i386? " << cosmos::arch::I386 << "\n";
	std::cout << "is x86_64? " << cosmos::arch::X86_64 << "\n";
	std::cout << "num_syscall_regs: " << clues::SYSCALL_MAX_PARS << "\n";

	clues::RegisterSet rs;
	std::cout << "RegisterSet: " << rs << std::endl;
	return 0;
}
