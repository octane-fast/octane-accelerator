#include <stdint.h>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

void randombytes(uint8_t *buf, uint64_t len) {
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#else
#include <fcntl.h>
#include <unistd.h>

void randombytes(uint8_t *buf, uint64_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return;
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n <= 0) break;
        buf += n;
        len -= (uint64_t)n;
    }
    close(fd);
}
#endif
