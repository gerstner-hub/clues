// C++
#include <iostream>

// Cosmos
#include <cosmos/cosmos.hxx>

// Clues
#include <clues/RegisterSet.hxx>
#include <clues/arch.hxx>

// Test
#include "TestBase.hxx"

class MiscTest : public cosmos::TestBase {
	void runTests() override {
		testArch();
	}

	void testArch() {
		START_TEST("arch detection");

		RUN_STEP("max pars >= 6", clues::SYSCALL_MAX_PARS >= 6);

		clues::RegisterSet rs;
		std::cout << "RegisterSet: " << rs << std::endl;
	}
};

int main(const int argc, const char **argv) {
	MiscTest test;
	return test.run(argc, argv);
}
