/*
 * Exercise the C half of ABI v1 the way an app does, and print what it got.
 *
 * This file is deliberately C and deliberately uses dlopen: it is the only
 * check in the repository that calls the shipped library through its published
 * header instead of through Rust. A Rust test would share the compiler's idea
 * of the signatures with the code under test, which is exactly the assumption
 * an ABI check is supposed to be free of.
 *
 * The frozen ABI-v1 ownership rules are asserted here rather than described: a
 * NULL buffer must report the required size, an undersized buffer
 * must not be written, and the required size must not change between calls.
 * Those are the three ways a caller from the *previous* app version would break
 * without the library ever failing a build.
 *
 * Build:  cc -o dump scripts/abi-capabilities-dump.c -ldl   (no -ldl on macOS)
 * Run:    ./dump /path/to/libfoxhole_native.{so,dylib}
 * Output: the capabilities document on stdout, diagnostics on stderr.
 */
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILL 0xAA

static void *must_sym(void *lib, const char *name) {
    void *symbol = dlsym(lib, name);
    if (symbol == NULL) {
        fprintf(stderr, "abi: exported symbol %s is missing\n", name);
        exit(1);
    }
    return symbol;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <library>\n", argv[0]);
        return 2;
    }

    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "abi: dlopen failed: %s\n", dlerror());
        return 2;
    }

    uint32_t (*abi_version)(void) = must_sym(lib, "foxhole_core_abi_version");
    uint32_t (*schema_version)(void) = must_sym(lib, "foxhole_core_config_schema_version");
    size_t (*json_len)(void) = must_sym(lib, "foxhole_core_capabilities_json_len");
    size_t (*json_write)(uint8_t *, size_t) = must_sym(lib, "foxhole_core_capabilities_json_write");

    size_t required = json_len();
    if (required == 0) {
        fprintf(stderr, "abi: capabilities_json_len reported 0\n");
        return 1;
    }

    /* A NULL buffer is how a caller asks for the size without allocating. */
    if (json_write(NULL, 0) != required) {
        fprintf(stderr, "abi: write(NULL, 0) did not report the required size\n");
        return 1;
    }

    /* An undersized buffer must be left untouched, not partially filled. */
    uint8_t *small = malloc(required);
    if (small == NULL) {
        fprintf(stderr, "abi: out of memory\n");
        return 2;
    }
    memset(small, FILL, required);
    if (json_write(small, required - 1) != required) {
        fprintf(stderr, "abi: an undersized write did not report the required size\n");
        return 1;
    }
    for (size_t index = 0; index < required; index++) {
        if (small[index] != FILL) {
            fprintf(stderr, "abi: an undersized write touched byte %zu\n", index);
            return 1;
        }
    }
    free(small);

    uint8_t *buffer = malloc(required + 1);
    if (buffer == NULL) {
        fprintf(stderr, "abi: out of memory\n");
        return 2;
    }
    memset(buffer, FILL, required + 1);
    if (json_write(buffer, required) != required) {
        fprintf(stderr, "abi: an exact-size write did not report the required size\n");
        return 1;
    }
    if (buffer[required - 1] != 0) {
        fprintf(stderr, "abi: the document is not NUL-terminated\n");
        return 1;
    }
    if (buffer[required] != FILL) {
        fprintf(stderr, "abi: the write ran past the buffer it was given\n");
        return 1;
    }
    /* The size is a property of the build, not of the call. */
    if (json_len() != required) {
        fprintf(stderr, "abi: the required size changed between calls\n");
        return 1;
    }

    fprintf(stderr, "abi_version=%u config_schema_version=%u bytes=%zu\n",
            (unsigned)abi_version(), (unsigned)schema_version(), required);
    fwrite(buffer, 1, required - 1, stdout);
    fputc('\n', stdout);

    free(buffer);
    return 0;
}
