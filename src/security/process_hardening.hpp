#ifndef VOID_VAULT_PROCESS_HARDENING_HPP
#define VOID_VAULT_PROCESS_HARDENING_HPP

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#endif

// Applies OS-level process mitigations at startup:
// - Disables core dumps / crash dumps so in-memory secrets cannot be written
//   to disk on abnormal termination.
// - Enables heap termination-on-corruption on Windows.
// - Marks the process non-dumpable / non-ptraceable on Linux.
inline void hardenProcess() noexcept
{
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
#else
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    (void)::setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__) && defined(PR_SET_DUMPABLE)
    (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
#endif
}

#endif
