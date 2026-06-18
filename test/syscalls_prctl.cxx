// test
#include "syscalls.hxx"

#ifdef CLUES_HAVE_ARCH_PRCTL
#include <asm/prctl.h>
#endif

namespace {

const auto TESTS = std::array{
#ifdef COSMOS_X86
	TestSpec{SystemCallNr::ARCH_PRCTL, []() {
			// disable SET_CPUID instruction
			syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
		}, ENTRY_VERIFY_CB(ArchPrctlSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ArchOpParameter::Operation::SET_CPUID);
			VERIFY_FALSE(sc.set_addr || sc.get_addr || sc.on_off_ret);
			VERIFY(sc.on_off->value() == 0);
		}), EXIT_VERIFY_CB(ArchPrctlSystemCall, {
			/* either success or ENODEV is to be expected for this
			 * test */
			VERIFY(!sc.hasErrorCode() || *sc.error()->errorCode() == cosmos::Errno::NO_DEVICE);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::ARCH_PRCTL, ARCH_SET_CPUID, 0);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_DUMPABLE, 1);
			prctl(PR_GET_DUMPABLE);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_DUMPABLE);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == true);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				prctl(PR_SET_DUMPABLE, 1);
				syscall32(SyscallNr32::PRCTL, PR_GET_DUMPABLE);
			})
		}, "GET_DUMPABLE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_DUMPABLE, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_DUMPABLE);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_DUMPABLE, 1);
			})
		}, "SET_DUMPABLE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_KEEPCAPS, 1);
			prctl(PR_GET_KEEPCAPS);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_KEEPCAPS);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == true);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				prctl(PR_SET_KEEPCAPS, 1);
				syscall32(SyscallNr32::PRCTL, PR_GET_KEEPCAPS);
			})
		}, "GET_KEEPCAPS"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_KEEPCAPS, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_KEEPCAPS);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_KEEPCAPS, 1);
			})
		}, "SET_KEEPCAPS"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_CHILD_SUBREAPER, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_CHILD_SUBREAPER);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_CHILD_SUBREAPER, 1);
			})
		}, "SET_CHILD_SUBREAPER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			long reaper = 0;
			prctl(PR_SET_CHILD_SUBREAPER, 1);
			prctl(PR_GET_CHILD_SUBREAPER, &reaper);
		}, ENTRY_VERIFY_CB(prctl::GetChildSubReaperSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_CHILD_SUBREAPER);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(sc.res.has_value());
		}), EXIT_VERIFY_CB(prctl::GetChildSubReaperSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.is_subreaper.value() == 1);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto reaper = alloc_struct32<long>();
				*reaper = 0;
				prctl(PR_SET_CHILD_SUBREAPER, 1);
				syscall32(SyscallNr32::PRCTL, PR_GET_CHILD_SUBREAPER, reaper);
			})
		}, "GET_CHILD_SUBREAPER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_GET_IO_FLUSHER);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_IO_FLUSHER);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			/* this call requires special permissions */
			(void)sc;
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_GET_IO_FLUSHER);
			})
		}, "GET_IO_FLUSHER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_IO_FLUSHER, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_IO_FLUSHER);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			(void)sc;
			/* this call requires special permissions */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_IO_FLUSHER, 1);
			})
		}, "SET_IO_FLUSHER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			/*
			 * this is the same pattern for most of the other
			 * operations dealing with start/end addresses of
			 * memory segments, thus we restrict ourselves to this
			 * one exemplary for the others or the same type..
			 */
			prctl(PR_SET_MM, PR_SET_MM_START_CODE, 0x1234);
		}, ENTRY_VERIFY_CB(prctl::MemoryMapSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::SET_MM);
			VERIFY(sc.mm_op.operation() == clues::item::MemoryMapOp::START_CODE);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.reported_size);
			VERIFY(!sc.exe_fd);
			VERIFY(!sc.mm_struct);
			VERIFY(!sc.mm_struct_size);
			VERIFY(sc.addr.has_value());
			VERIFY(cosmos::to_integral(sc.addr->ptr()) == 0x1234);
		}), EXIT_VERIFY_CB(prctl::MemoryMapSystemCall, {
			(void)sc;
			/* this call requires special permissions */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_MM,
						PR_SET_MM_START_CODE, 0x1234);
			})
		}, "SET_MM:START_CODE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			/*
			 * this passes a file descriptor instead of an address
			 */
			prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, 3);
		}, ENTRY_VERIFY_CB(prctl::MemoryMapSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::SET_MM);
			VERIFY(sc.mm_op.operation() == clues::item::MemoryMapOp::EXE_FILE);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.reported_size);
			VERIFY(!sc.mm_struct);
			VERIFY(!sc.mm_struct_size);
			VERIFY(!sc.addr);
			VERIFY(sc.exe_fd->fd() == cosmos::FileNum{3});
		}), EXIT_VERIFY_CB(prctl::MemoryMapSystemCall, {
			(void)sc;
			/* this call requires special permissions */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_MM,
						PR_SET_MM_EXE_FILE, 3);
			})
		}, "SET_MM:EXE_FILE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			/*
			 * this receives the expected struct size to an out
			 * pointer.
			 */
			unsigned int map_size = 0;
			prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &map_size, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::MemoryMapSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::SET_MM);
			VERIFY(sc.mm_op.operation() == clues::item::MemoryMapOp::MAP_SIZE);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.mm_struct);
			VERIFY(!sc.addr);
			VERIFY(!sc.exe_fd);
			VERIFY(!sc.mm_struct_size);
			VERIFY(sc.reported_size.has_value());
		}), EXIT_VERIFY_CB(prctl::MemoryMapSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto map_size = *sc.reported_size->value();
			VERIFY(map_size >= sizeof(prctl_mm_map));
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto map_size = alloc_struct32<unsigned int>();
				*map_size = 0;
				syscall32(SyscallNr32::PRCTL, PR_SET_MM,
						PR_SET_MM_MAP_SIZE, map_size, 0, 0);
			})
		}, "SET_MM:MAP_SIZE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			/* takes a struct containing all the memory mapping information */
			prctl_mm_map map;
			map.start_code = 0x1234;
			map.end_code = 0x4321;
			map.start_data = 0x2345;
			map.end_data = 0x5432;
			map.start_brk = 0x3456;
			map.brk = 0x6543;
			map.start_stack = 0x4567;
			map.arg_start = 0x5678;
			map.arg_end = 0x8765;
			map.env_start = 0x6789;
			map.env_end = 0x9876;
			map.auxv = (__u64*)0x7890;
			map.auxv_size = 0x123;
			map.exe_fd = 14;
			prctl(PR_SET_MM, PR_SET_MM_MAP, &map, sizeof(map), 0);
		}, ENTRY_VERIFY_CB(prctl::MemoryMapSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::SET_MM);
			VERIFY(sc.mm_op.operation() == clues::item::MemoryMapOp::MAP);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.addr);
			VERIFY(!sc.exe_fd);
			VERIFY(!sc.reported_size);
			VERIFY(sc.mm_struct);
			VERIFY(sc.mm_struct_size);
			VERIFY(sc.mm_struct_size->value() == sizeof(prctl_mm_map));
			const auto &map = *sc.mm_struct->map();
			/* only check the start and end attributes of the
			 * struct to keep things brief */
			VERIFY(map.start_code == 0x1234);
			VERIFY(map.exe_fd == 14);
		}), EXIT_VERIFY_CB(prctl::MemoryMapSystemCall, {
			(void)sc;
			/* this call requires elevated privileges to succeed */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto map = alloc_struct32<prctl_mm_map>();;
				map->start_code = 0x1234;
				map->end_code = 0x4321;
				map->start_data = 0x2345;
				map->end_data = 0x5432;
				map->start_brk = 0x3456;
				map->brk = 0x6543;
				map->start_stack = 0x4567;
				map->arg_start = 0x5678;
				map->arg_end = 0x8765;
				map->env_start = 0x6789;
				map->env_end = 0x9876;
				map->auxv = (__u64*)0x7890;
				map->auxv_size = 0x123;
				map->exe_fd = 14;
				syscall32(SyscallNr32::PRCTL, PR_SET_MM, PR_SET_MM_MAP, map, sizeof(*map), 0);
			})
		}, "SET_MM:MAP"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_MCE_KILL, PR_MCE_KILL_SET,
					PR_MCE_KILL_EARLY, 0, 0);
			prctl(PR_MCE_KILL_GET, 0, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::MachineCheckKillGetSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::MCE_KILL_GET);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(!sc.res);
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(prctl::MachineCheckKillGetSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.policy_res.policy() ==
					clues::item::MachineCheckPolicy::KILL_EARLY);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				prctl(PR_MCE_KILL, PR_MCE_KILL_SET,
						PR_MCE_KILL_EARLY, 0, 0);
				syscall32(SyscallNr32::PRCTL,
						PR_MCE_KILL_GET, 0, 0, 0, 0);
			})
		}, "MCE_KILL_GET"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::MachineCheckKillSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::MCE_KILL);
			VERIFY(sc.mce_kill_op.operation() ==
					clues::item::MachineCheckOp::CLEAR);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(prctl::MachineCheckKillSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0);
			})
		}, "MCE_KILL:CLEAR"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::MachineCheckKillSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::MCE_KILL);
			VERIFY(sc.mce_kill_op.operation() ==
					clues::item::MachineCheckOp::SET);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(sc.policy->policy() ==
					clues::item::MachineCheckPolicy::KILL_EARLY);
		}), EXIT_VERIFY_CB(prctl::MachineCheckKillSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_MCE_KILL, PR_MCE_KILL_SET,
						PR_MCE_KILL_EARLY, 0, 0);
			})
		}, "MCE_KILL:SET"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::CapAmbientSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ProcessOp::CAP_AMBIENT);
			VERIFY(sc.ambient_op.operation() == clues::item::AmbientCapOp::CLEAR_ALL);
			VERIFY(!sc.cap);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(prctl::CapAmbientSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_CAP_AMBIENT,
						PR_CAP_AMBIENT_CLEAR_ALL,
						0, 0, 0);
			})
		}, "CAP_AMBIENT:CLEAR_ALL"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::CapAmbientSystemCall, {
			/* CAP_AMBIENT_RAISE is mostly the same, only that
			 * we're lacking permission to do it, so let's stick
			 * to this single test case */
			VERIFY(sc.op.operation() == clues::item::ProcessOp::CAP_AMBIENT);
			VERIFY(sc.ambient_op.operation() == clues::item::AmbientCapOp::LOWER);
			VERIFY(sc.cap.has_value());
			VERIFY(sc.cap->cap() == cosmos::Capability::SYS_ADMIN);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(prctl::CapAmbientSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_CAP_AMBIENT,
						PR_CAP_AMBIENT_LOWER,
						CAP_SYS_ADMIN, 0, 0);
			})
		}, "CAP_AMBIENT:LOWER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::CapAmbientSystemCall, {
			/* CAP_AMBIENT_RAISE is mostly the same, only that
			 * we're lacking permission to do it, so let's stick
			 * to this single test case */
			VERIFY(sc.op.operation() == clues::item::ProcessOp::CAP_AMBIENT);
			VERIFY(sc.ambient_op.operation() == clues::item::AmbientCapOp::IS_SET);
			VERIFY(sc.cap.has_value());
			VERIFY(sc.cap->cap() == cosmos::Capability::NET_ADMIN);
			VERIFY(!sc.res);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(prctl::CapAmbientSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == false);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_CAP_AMBIENT,
						PR_CAP_AMBIENT_IS_SET,
						CAP_NET_ADMIN, 0, 0);
			})
		}, "CAP_AMBIENT:IS_SET"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_CAPBSET_READ, CAP_NET_ADMIN);
		}, ENTRY_VERIFY_CB(prctl::CapBSetSystemCall, {
			/* CAP_AMBIENT_RAISE is mostly the same, only that
			 * we're lacking permission to do it, so let's stick
			 * to this single test case */
			VERIFY(sc.op.operation() == clues::item::ProcessOp::CAPBSET_READ);
			VERIFY(sc.cap.cap() == cosmos::Capability::NET_ADMIN);
			VERIFY(!sc.res);
			VERIFY(!sc.bool_setting);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(prctl::CapBSetSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == true);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_CAPBSET_READ,
						CAP_NET_ADMIN, 0, 0, 0);
			})
		}, "CAPBSET_READ"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_CAPBSET_DROP, CAP_NET_RAW);
		}, ENTRY_VERIFY_CB(prctl::CapBSetSystemCall, {
			/* CAP_AMBIENT_RAISE is mostly the same, only that
			 * we're lacking permission to do it, so let's stick
			 * to this single test case */
			VERIFY(sc.op.operation() == clues::item::ProcessOp::CAPBSET_DROP);
			VERIFY(sc.cap.cap() == cosmos::Capability::NET_RAW);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(prctl::CapBSetSystemCall, {
			(void)sc;
			/* this call requires special privileges to suceed */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_CAPBSET_DROP,
						CAP_NET_RAW, 0, 0, 0);
			})
		}, "CAPBSET_DROP"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			auto addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr,
					4096, "testname");
		}, ENTRY_VERIFY_CB(prctl::VirtualMemoryAttrSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_VMA);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.bool_res);
			VERIFY(sc.attr.attr() ==
					clues::item::VirtualMemoryAttr::ANON_NAME);
			VERIFY(sc.addr.ptr() != clues::ForeignPtr::NO_POINTER);
			VERIFY(sc.size.value() == 4096);
			VERIFY(sc.name.has_value());
			VERIFY(*sc.name->data() == "testname");
		}), EXIT_VERIFY_CB(prctl::VirtualMemoryAttrSystemCall, {
			/* this call can fail with EINVAL if kernel support is
			 * lacking */
			(void)sc;
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto name = alloc_str32("testname");
				auto addr = mmap(NULL, 4096,
						PROT_READ|PROT_WRITE,
						MAP_PRIVATE|MAP_32BIT|MAP_ANONYMOUS,
						-1, 0);
				syscall32(SyscallNr32::PRCTL,
						PR_SET_VMA,
						PR_SET_VMA_ANON_NAME,
						addr,
						4096, name);
			})
		}, "PR_SET_VMA"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_NAME, "testname");
		}, ENTRY_VERIFY_CB(prctl::NameSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_NAME);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.bool_res);
			VERIFY(sc.name.has_value());
			VERIFY(sc.name->data() == "testname");
		}), EXIT_VERIFY_CB(prctl::NameSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto name = alloc_str32("testname");
				syscall32(SyscallNr32::PRCTL,
						PR_SET_NAME,
						name);
			})
		}, "PR_SET_NAME"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_NAME, "testname");
			char name[16];
			prctl(PR_GET_NAME, name);
		}, ENTRY_VERIFY_CB(prctl::NameSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_NAME);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.bool_res);
			VERIFY(sc.name.has_value());
		}), EXIT_VERIFY_CB(prctl::NameSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.name->data() == "testname");
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto name = alloc_str32("testname");
				syscall32(SyscallNr32::PRCTL,
						PR_SET_NAME,
						name);
				auto outname = alloc32<char*>(16);
				syscall32(SyscallNr32::PRCTL,
						PR_GET_NAME,
						outname);
			})
		}, "PR_GET_NAME"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_NO_NEW_PRIVS);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_SET_NO_NEW_PRIVS,
						1, 0, 0, 0);
			})
		}, "PR_SET_NO_NEW_PRIVS"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_PDEATHSIG, SIGSEGV, 0, 0, 0);
			long sig = 0;
			prctl(PR_GET_PDEATHSIG, &sig, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::ParentDeathSignalSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_PDEATHSIG);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(!sc.new_signal);
			VERIFY(sc.cur_signal.has_value());
		}), EXIT_VERIFY_CB(prctl::ParentDeathSignalSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.cur_signal->value() == cosmos::SignalNr::SEGV);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				prctl(PR_SET_PDEATHSIG, SIGSEGV, 0, 0, 0);
				auto sig = alloc_struct32<long>();
				syscall32(SyscallNr32::PRCTL,
						PR_GET_PDEATHSIG,
						sig, 0, 0, 0);
			})
		}, "PR_GET_PDEATHSIG"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_PDEATHSIG, SIGSEGV, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::ParentDeathSignalSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_PDEATHSIG);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(!sc.cur_signal);
			VERIFY(sc.new_signal.has_value());
			VERIFY(sc.new_signal->nr() == cosmos::SignalNr::SEGV);
		}), EXIT_VERIFY_CB(prctl::ParentDeathSignalSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_SET_PDEATHSIG,
						SIGSEGV, 0, 0, 0);
			})
		}, "PR_SET_PDEATHSIG"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_PTRACER, 1, 0, 0, 0);
		}, ENTRY_VERIFY_CB(prctl::SetPTracerSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_PTRACER);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
			VERIFY(!sc.bool_setting.has_value());
			VERIFY(sc.pid.pid() == cosmos::ProcessID{1});
		}), EXIT_VERIFY_CB(prctl::SetPTracerSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL,
						PR_SET_PTRACER,
						1, 0, 0, 0);
			})
		}, "PR_SET_PTRACER"
	},
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
