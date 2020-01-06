// C++
#include <iostream>

// Clues
#include "clues/RegisterSet.hxx"
#include "clues/Arch.hxx"
#include "clues/Init.hxx"

int main()
{
	clues::Init init;
	std::cout << "is i386? " << clues::isi386() << "\n";
	std::cout << "is x86_64? " << clues::isx86_64() << "\n";
	std::cout << "num_syscall_regs: " << clues::MAX_SYSCALL_PARS << "\n";

	clues::RegisterSet rs(true);
	std::cout << "RegisterSet: " << rs << std::endl;
	return 0;
}
