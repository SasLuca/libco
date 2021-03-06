# Single header version of libco

**Download the [single header here](https://raw.githubusercontent.com/SasLuca/libco/master/generated/libco.h) or from the `generated` directory**.

This is a single header version of `libco` by Byuu (https://byuu.org/projects/libco), which is a portable library for coroutines in C.
The single header version is manually concatenated from a `libco` fork by @edsiper (https://github.com/edsiper/flb_libco).
This was mainly created for convenience and ease of use.

All concatenated files are placed in `#pragma region`/`#pragma endregion` blocks for easy collapse and visualization in an editor.
All `#include` statements from the concatenated files have been commented out and if a file has been concatenated in their place then the statement is followed by a `#pragma region`.

Define `LIBCO_IMPLEMENTATION` in one translation unit in order to include the implementation like so:
```c
#define LIBCO_IMPLEMENTATION 
#include "libco.h"
```

## Existing backends:
- x86 CPUs
- amd64 CPUs
- PowerPC CPUs
- PowerPC64 ELFv1 CPUs
- PowerPC64 ELFv2 CPUs
- ARM 32-bit CPUs
- ARM 64-bit (AArch64) CPUs
- POSIX platforms (setjmp)
- Windows platforms (fibers)

## Compile time options:

- `#define LIBCO_IMPLEMENTATION` -> Include the implementation.

- `#define LIBCO_MP` -> Allows the use `thread_local`. (Note: Doesn't work with `mingw` for some reason)

- `#define LIBCO_NO_SSE` -> Provides a substantial speed-up on Win64 only but it will trash XMM registers. Only use this if you are sure your application or it's dependencies don't use SSE explicitly.

- `#define LIBCO_MPROTECT` -> On `[amd64, arm, ppc, x86]` this will enable the use of `mprotect` instead of marking `co_swap_function` as a `text` (code) section.

## API:

- `cothread_t co_active()` -> Returns a reference to the currently active cothread on the current thread. 
- `cothread_t co_create(unsigned int, void (*)(void), size_t *)` -> Creates a new cothread given a stack size and an entry point. The last argument is an out-parameter to get the actual stack size that the cothread will receive, you can pass `NULL` to ignore it. 
- `void co_delete(cothread_t)` -> Deletes a cothread.
- `void co_switch(cothread_t)` -> Yield from the current cothread to another.

## Example:

```cpp
#define LIBCO_IMPLEMENTATION

#include "stdio.h"
#include "libco.h"

cothread_t main_cothread;

void my_entry(void)
{
    int i = 0;
    while (1)
    {
        printf("%d\n", i++);

        // Yield to main cothread
        co_switch(main_cothread);
    }
}

int main()
{
    // Get reference to the main cthread
    main_cothread = co_active();

    // Init separate cothread
    cothread_t other_cothread = co_create(1 * 1024 * 1024, my_entry, NULL);

    // Yield to the cothread
    co_switch(other_cothread);
    co_switch(other_cothread);
    co_switch(other_cothread);

    // Delete the other cothread
    co_delete(other_cothread);
}
```