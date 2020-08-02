// Linux

// Cosmos
#include "cosmos/errors/UsageError.hxx"

// Clues
#include "clues/Arch.hxx"

using namespace cosmos;

namespace clues
{

const char* getRegisterName(const size_t number)
{
	switch(number)
	{
	default: cosmos_throw( UsageError("Invalid register number encountered") );
#ifdef __x86_64__
	case R15: return "R15";
	case R14: return "R14";
	case R13: return "R13";
	case R12: return "R12";
	case RBP: return "RBP";
	case RBX: return "RBX";
	case R11: return "R11";
	case R10: return "R10";
	case R9: return "R9";
	case R8: return "R8";
	case RAX: return "RAX";
	case RCX: return "RCX";
	case RDX: return "RDX";
	case RSI: return "RSI";
	case RDI: return "RDI";
	case ORIG_RAX: return "ORIG_RAX";
	case RIP: return "RIP";
	case CS: return "CS";
	case EFLAGS: return "AGS";
	case RSP: return "RSP";
	case SS: return "SS";
	case FS_BASE: return "FS_BASE";
	case GS_BASE: return "GS_BASE";
	case DS: return "DS";
	case ES: return "ES";
	case FS: return "FS";
	case GS: return "GS";
#elif defined(__i386__)
	case EBX: return "EBX";
	case ECX: return "ECX";
	case EDX: return "EDX";
	case ESI: return "ESI";
	case EDI: return "EDI";
	case EBP: return "EBP";
	case EAX: return "EAX";
	case DS: return "DS";
	case ES: return "ES";
	case FS: return "FS";
	case GS: return "GS";
	case ORIG_EAX: return "ORIG_EAX";
	case EIP: return "EIP";
	case CS: return "CS";
	case EFL: return "EFL";
	case UESP: return "UESP";
	case SS: return "SS";
#elif defined(__arm__)
	#warning "ARM not yet implemented"
#else
#	error "not yet supported architecture"
#endif
	} // end switch
}

} // end ns
