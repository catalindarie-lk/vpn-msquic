#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdatomic.h>
#include <inttypes.h>

// static uint64_t cnt = 0;

// --- Compiler Portability Attribute for Unused Static Functions ---
#if defined(__GNUC__) || defined(__clang__)
    #define LOG_UNUSED __attribute__((unused))
#else
    #define LOG_UNUSED
#endif

// --- Configurable Logging Tiers (Override via build system or -D flags) ---
#ifndef ENABLE_LOG_ERROR
    #define ENABLE_LOG_ERROR 1
#endif

#ifndef ENABLE_LOG_WARNING
    #define ENABLE_LOG_WARNING 1
#endif

#ifndef DEBUG_LEVEL
    #define DEBUG_LEVEL 1 // 0 = OFF, 1 = Simple, 2 = Verbose
#endif

#ifndef TRACE_LEVEL
    #define TRACE_LEVEL 1 // 0 = OFF, 1 = Simple, 2 = Verbose
#endif

// --- Helper Implementations ---

static inline LOG_UNUSED void log_error_impl(const char *file, int line, const char *func, const char *fmt, ...) {
    fprintf(stderr, "[-] [err] [%s:%d in %s()]: ", file, line, func);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

static inline LOG_UNUSED void log_warning_impl(const char *file, int line, const char *func, const char *fmt, ...) {
    fprintf(stdout, "[!] [wrn]  [%s:%d in %s()]: ", file, line, func);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stderr);
}

static inline LOG_UNUSED void log_debug_impl(const char *fmt, ...) {
    fprintf(stdout, "[dbg]: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stderr);
}

static inline LOG_UNUSED void log_debug_verbose_impl(const char *file, int line, const char *func, const char *fmt, ...) {
    fprintf(stdout, "[dbg] [%s:%d in %s()]: ", file, line, func);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stderr);
}

static inline LOG_UNUSED void log_trace_impl(const char *fmt, ...) {
    fprintf(stdout, "[trace]: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stderr);
}

static inline LOG_UNUSED void log_trace_verbose_impl(const char *file, int line, const char *func, const char *fmt, ...) {
    fprintf(stdout, "[trace] [%s:%d in %s()]: ", file, line, func);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stderr);
}

// --- User-Facing Logging Macros ---

// ERROR
#if (ENABLE_LOG_ERROR == 1)
    #define LOG_ERROR(fmt, ...) \
        log_error_impl(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#else
    #define LOG_ERROR(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

// WARNING
#if (ENABLE_LOG_WARNING == 1)
    #define LOG_WARNING(fmt, ...) \
        log_warning_impl(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#else
    #define LOG_WARNING(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

// DEBUG
#if (DEBUG_LEVEL == 2)
    #define LOG_DEBUG(fmt, ...) \
        log_debug_verbose_impl(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#elif (DEBUG_LEVEL == 1)
    #define LOG_DEBUG(fmt, ...) \
        log_debug_impl(fmt, ##__VA_ARGS__)
#else 
    #define LOG_DEBUG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

// TRACE
#if (TRACE_LEVEL == 2)
    #define LOG_TRACE(fmt, ...) \
        log_trace_verbose_impl(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#elif (TRACE_LEVEL == 1)
    #define LOG_TRACE(fmt, ...) \
        log_trace_impl(fmt, ##__VA_ARGS__)
#else 
    #define LOG_TRACE(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

#endif // LOG_H