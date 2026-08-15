#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <limits.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#include <spawn.h>
#include <sys/wait.h>

#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef htonll
#   if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#       define htonll(x) __builtin_bswap64((uint64_t)(x))
#       define ntohll(x) __builtin_bswap64((uint64_t)(x))
#   elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#       define htonll(x) ((uint64_t)(x))
#       define ntohll(x) ((uint64_t)(x))
#   else
#       error "Unable to determine host byte order for htonll"
#   endif
#endif


#ifndef SSIZE_MAX
#  if defined(_WIN64)
#    define SSIZE_MAX INTPTR_MAX
#  elif defined(_WIN32)
#    define SSIZE_MAX INT_MAX
#  else
#    define SSIZE_MAX ((ssize_t)(~0UL >> 1))
#  endif
#endif

/* 
 * 4. Extensible Diagnostic Logging Macro
 */
#ifndef FATAL
#define FATAL(...) do { \
    (void)fflush(stdout); \
    (void)fprintf(stderr, "[FATAL] [%s:%d in function '%s'()]: ", __FILE__, __LINE__, __FUNCTION__); \
    (void)fprintf(stderr, __VA_ARGS__); \
    (void)fprintf(stderr, "\n"); \
    (void)fflush(stderr); \
    abort(); \
} while (0)
#endif /* FATAL */

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000000000ULL +
           (uint64_t)ts.tv_nsec;
}

/**
 * Checks a list of candidate absolute paths and returns the first 
 * executable file found.
 *
 * @param paths NULL-terminated array of absolute file paths
 * @return Pointer to the first matching path string, or NULL if none exist
 */
static inline const char* find_binary(char *const paths[]) {
    for (int i = 0; paths[i] != NULL; i++) {
        // F_OK checks if file exists, X_OK checks if current process has permission to execute it
        if (access(paths[i], F_OK | X_OK) == 0) {
            return paths[i]; // Found valid executable path!
        }
    }
    return NULL;
}

/**
 * Safely executes a verified binary using posix_spawn().
 *
 * @param path Verified absolute path (e.g. "/usr/sbin/iptables")
 * @param argv NULL-terminated array of arguments
 * @return Exit status of the process (0 on success), or -1 on critical execution failure
 */
static inline int run_command(const char *path, char *const argv[]) {
    // CRITICAL ERROR: Always log invalid inputs
    if (!path) {
        LOG_ERROR("Invalid/NULL binary path provided");
        return -EINVAL;
    }

    pid_t pid;
    int status;

    // Hardened, minimal environment to avoid leaking sensitive parent env vars
    char *const minimal_env[] = {
        "LC_ALL=C", // Ensures consistent POSIX error string output
        NULL
    };

    // Spawn process using explicit path
    int result = posix_spawn(&pid, path, NULL, NULL, argv, minimal_env);

    // CRITICAL ERROR: Always log posix_spawn failure (e.g., ENOENT, E2BIG, ENOMEM)
    if (result != 0) {
        LOG_ERROR("posix_spawn failed for '%s': %s", path, strerror(result));
        return -result;
    }

    // CRITICAL ERROR: Always log kernel/waitpid failures
    if (waitpid(pid, &status, 0) == -1) {
        LOG_ERROR("waitpid failed for '%s': %s", path, strerror(errno));
        return -errno;
    }

    // COMMAND EXIT STATUS HANDLING
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status); // Returns 0 on command success, non-zero (e.g. 1) otherwise
    }

    // CRITICAL ERROR: Always log abnormal process termination (e.g., killed by SIGSEGV or SIGKILL)
    if (WIFSIGNALED(status)) {
        LOG_ERROR("Process '%s' terminated by signal %d", path, WTERMSIG(status));
    }

    return -ECHILD;
}


static inline bool validate_mask(const struct in_addr* mask) {
    
    uint32_t ntoh_mask = ntohl(mask->s_addr);

    if (ntoh_mask == 0) {
        return true; // 0.0.0.0 (/0) is valid
    }

    // Invert mask: valid contiguous mask becomes contiguous 1s on the right
    uint32_t inverted = ~ntoh_mask;

    // Adding 1 to a contiguous block of 1s turns it into a power of 2
    // e.g. 0x000000FF + 1 = 0x00000100. (0x00000100 & 0x000000FF) == 0.
    return ((inverted + 1) & (inverted)) == 0;
    // return (((~ntoh_mask) + 1) & (~ntoh_mask)) == 0;
}

static inline int in_addr_to_cidr(const struct in_addr *addr, 
        const struct in_addr *mask, char *out_cidr, size_t cidr_len) {
            
    int err = 0;

    if (!addr || !mask || !out_cidr) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    // Validate that the mask bits are contiguous (catches 255.0.255.0)
    if (!validate_mask(mask)) {
        LOG_ERROR("Non-contiguous subnet mask");
        return -EINVAL;
    }

    // Convert netmask from Network Byte Order to Host Byte Order
    uint32_t ntoh_mask = ntohl(mask->s_addr);

    // Count set bits
    uint8_t prefix = (uint8_t)__builtin_popcount(ntoh_mask);

    char addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str)) == NULL) {
        err = -errno;
        LOG_ERROR("inet_ntop() failure");
        return err;
    }

    snprintf(out_cidr, cidr_len, "%s/%u", addr_str, prefix);

    return 0;
}

/* Converts struct in_addr to string representation */
static inline int in_addr_to_str(const struct in_addr *addr, char *buf, size_t buf_len) {
    if (!addr || !buf || buf_len == 0) return -EINVAL;
    if (inet_ntop(AF_INET, addr, buf, buf_len) == NULL) {
        return -errno;
    }
    return 0;
}

static inline int8_t mask_to_prefix(const struct in_addr* mask){

    // Validate that the mask bits are contiguous (catches 255.0.255.0)
    if (!validate_mask(mask)) {
        LOG_ERROR("Non-contiguous subnet mask");
        return -EINVAL;
    }

    uint32_t ntoh_mask = ntohl(mask->s_addr);
    // Count set bits safely now that we verified contiguity
    uint8_t prefix = (uint8_t)__builtin_popcount(ntoh_mask);

    return (int8_t)prefix;
}

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */