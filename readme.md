# Single header version of libco

**Download the [single header here](https://raw.githubusercontent.com/SasLuca/libco/master/generated/libco.h) or from the `generated` directory**.

This is a single header version of `libco` by Byuu (https://byuu.org/projects/libco), which is a portable library for coroutines in C.
The single header version is manually concatenated from a `libco` fork by @edsiper (https://github.com/edsiper/flb_libco).

All concatenated files are placed in `#pragma region`/`#pragma endregion` blocks for easy collapse and visualization in an editor.
All `#include` statements from the concatenated files have been commented out and if a file has been concatenated in their place then the statement is followed by a `#pragma region`.

# Options:

1. `#define LIBCO_MP` -> allow the use of `thread_local`. (Note: Doesn't work with `mingw` for some reason)

2. `#define LIBCO_NO_SSE` -> provides a substantial speed-up on Win64 only but it will trash XMM registers. Only use this if you are sure your application or it's dependencies don't use SSE explicitly.

3. `#define LIBCO_MPROTECT` -> On `[amd64, arm, ppc, x86]` this will enable the use of `mprotect` instead of marking `co_swap_function` as a `text` (code) section.

# Example:

```cpp
#define LIBCO_IMPLEMENTATION

#include "stdlib.h"
#include "stdio.h"
#include "libco.h"

// main_thread
cothread_t main_cothread;

void my_entry()
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
    size_t actual_size = 0;
    size_t request_size = 1 * 1024 * 1024;
    cothread_t other_cothread = co_create(request_size, my_entry, &actual_size);
    
    // Yield to the cothread
    co_switch(other_cothread);
    co_switch(other_cothread);
    co_switch(other_cothread);
    
    // Delete the other cothread
    co_delete(other_cothread);
}
```
