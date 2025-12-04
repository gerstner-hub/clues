// C++
#include <iostream>

// Cosmos
#include <cosmos/cosmos.hxx>

// Clues
#include <clues/RegisterSet.hxx>
#include <clues/regs/traits.hxx>
#include <clues/utils.hxx>

// Test
#include "TestBase.hxx"

class MiscTest : public cosmos::TestBase {
	void runTests() override {
		testArch();
	}

	void testArch() {
		START_TEST("arch detection");

		const auto OUR_ABI = clues::get_default_abi();
		using OurRegisterData = clues::RegisterDataTraits<OUR_ABI>::type;
		RUN_STEP("max pars >= 6", OurRegisterData::NUM_SYSCALL_PARS >= 6);

		clues::RegisterSet<OUR_ABI> rs;
		std::cout << "RegisterSet: " << rs << std::endl;
	}
};

int main(const int argc, const char **argv) {
	MiscTest test;
	return test.run(argc, argv);
}
