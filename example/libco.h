/*

Single header version of the libco (https://github.com/SasLuca/libco).

This is a single header version of libco by Byuu (https://byuu.org/projects/libco), which is a portable library for coroutines in C.
The single header version is manually concatenated from a libco fork by @edsiper (https://github.com/edsiper/flb_libco).

Define LIBCO_IMPLEMENTATION in one translation unit in order to include the implementation like so:
```c
#define LIBCO_IMPLEMENTATION
#include "libco.h"
```

Existing backends:
- x86 CPUs
- amd64 CPUs
- PowerPC CPUs
- PowerPC64 ELFv1 CPUs
- PowerPC64 ELFv2 CPUs
- ARM 32-bit CPUs
- ARM 64-bit (AArch64) CPUs
- POSIX platforms (setjmp)
- Windows platforms (fibers)

Compile time options:

#define LIBCO_IMPLEMENTATION -> Include the implementation.

#define LIBCO_MP -> allow the use thread_local. (Note: Doesn't work with mingw for some reason)

#define LIBCO_NO_SSE -> provides a substantial speed-up on Win64 only but it will trash XMM registers. Only use this if you are sure your application or it's dependencies don't use SSE explicitly.

#define LIBCO_MPROTECT -> On [amd64, arm, ppc, x86] this will enable the use of mprotect instead of marking co_swap_function as a text (code) section.

API:

- cothread_t co_active() -> Returns a reference to the currently active cothread on the current thread.
- cothread_t co_create(unsigned int, void (*)(void), size_t *) -> Creates a new cothread given a stack size and an entry point. The last argument is an out-parameter to get the actual stack size that the cothread will receive, you can pass `NULL` to ignore it.
- void co_delete(cothread_t) -> Deletes a cothread.
- void co_switch(cothread_t) -> Yield from the current cothread to another.

Example:

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

*/

#pragma region libco.h

/*
  libco v18 (2016-09-14)
  author: byuu
  license: public domain
*/

#ifndef LIBCO_H
#define LIBCO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* cothread_t;

cothread_t co_active();
cothread_t co_create(unsigned int, void (*)(void), size_t *);
void co_delete(cothread_t);
void co_switch(cothread_t);

#ifdef __cplusplus
}
#endif

/* ifndef LIBCO_H */
#endif

#pragma endregion

#ifdef LIBCO_IMPLEMENTATION

#pragma region libco.c

/*
  libco
  license: public domain
*/

#if defined(__clang__)
  #pragma clang diagnostic ignored "-Wparentheses"
#endif

#if defined(__clang__) || defined(__GNUC__)
  #if defined(__i386__)
    //#include "x86.c"
    #pragma region x86.c
/*
  libco.x86 (2016-09-14)
  author: byuu
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#include <assert.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__) || defined(__GNUC__)
  #define fastcall __attribute__((fastcall))
#elif defined(_MSC_VER)
  #define fastcall __fastcall
#else
  #error "libco: please define fastcall macro"
#endif

static thread_local long co_active_buffer[64];
static thread_local cothread_t co_active_handle = 0;
static void (fastcall *co_swap)(cothread_t, cothread_t) = 0;

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  text_section
#endif
/* ABI: fastcall */
static const unsigned char co_swap_function[4096] = {
  0x89, 0x22,        /* mov [edx],esp    */
  0x8b, 0x21,        /* mov esp,[ecx]    */
  0x58,              /* pop eax          */
  0x89, 0x6a, 0x04,  /* mov [edx+ 4],ebp */
  0x89, 0x72, 0x08,  /* mov [edx+ 8],esi */
  0x89, 0x7a, 0x0c,  /* mov [edx+12],edi */
  0x89, 0x5a, 0x10,  /* mov [edx+16],ebx */
  0x8b, 0x69, 0x04,  /* mov ebp,[ecx+ 4] */
  0x8b, 0x71, 0x08,  /* mov esi,[ecx+ 8] */
  0x8b, 0x79, 0x0c,  /* mov edi,[ecx+12] */
  0x8b, 0x59, 0x10,  /* mov ebx,[ecx+16] */
  0xff, 0xe0,        /* jmp eax          */
};

#ifdef _WIN32
  #include <windows.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    DWORD old_privileges;
    VirtualProtect((void*)co_swap_function, sizeof co_swap_function, PAGE_EXECUTE_READ, &old_privileges);
    #endif
  }
#else
  #include <unistd.h>
  #include <sys/mman.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    unsigned long addr = (unsigned long)co_swap_function;
    unsigned long base = addr - (addr % sysconf(_SC_PAGESIZE));
    unsigned long size = (addr - base) + sizeof co_swap_function;
    mprotect((void*)base, size, PROT_READ | PROT_EXEC);
    #endif
  }
#endif

static void crash() {
  assert(0);  /* called only if cothread_t entrypoint returns */
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  return co_active_handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size) {
  cothread_t handle;
  if(!co_swap) {
    co_init();
    co_swap = (void (fastcall*)(cothread_t, cothread_t))co_swap_function;
  }
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  size += 256;  /* allocate additional space for storage */
  size &= ~15;  /* align stack to 16-byte boundary */
  if (out_size) *out_size = size;

  if(handle = (cothread_t)malloc(size)) {
    long *p = (long*)((char*)handle + size);  /* seek to top of stack */
    *--p = (long)crash;                       /* crash if entrypoint returns */
    *--p = (long)entrypoint;                  /* start of function */
    *(long*)handle = (long)p;                 /* stack pointer */
  }

  return handle;
}

void co_delete(cothread_t handle) {
  free(handle);
}

void co_switch(cothread_t handle) {
  register cothread_t co_previous_handle = co_active_handle;
  co_swap(co_active_handle = handle, co_previous_handle);
}

#ifdef __cplusplus
}
#endif

#pragma endregion
  #elif defined(__amd64__)
    //#include "amd64.c"
    #pragma region amd64.c
    /*
  libco.amd64 (2016-09-14)
  author: byuu
  license: public domain
*/

#define LIBCO_C
////#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion


#include <assert.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local long long co_active_buffer[64];
static thread_local cothread_t co_active_handle = 0;
static void (*co_swap)(cothread_t, cothread_t) = 0;

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  text_section
#endif
#ifdef _WIN32
  /* ABI: Win64 */
  static const unsigned char co_swap_function[4096] = {
    0x48, 0x89, 0x22,              /* mov [rdx],rsp          */
    0x48, 0x8b, 0x21,              /* mov rsp,[rcx]          */
    0x58,                          /* pop rax                */
    0x48, 0x89, 0x6a, 0x08,        /* mov [rdx+ 8],rbp       */
    0x48, 0x89, 0x72, 0x10,        /* mov [rdx+16],rsi       */
    0x48, 0x89, 0x7a, 0x18,        /* mov [rdx+24],rdi       */
    0x48, 0x89, 0x5a, 0x20,        /* mov [rdx+32],rbx       */
    0x4c, 0x89, 0x62, 0x28,        /* mov [rdx+40],r12       */
    0x4c, 0x89, 0x6a, 0x30,        /* mov [rdx+48],r13       */
    0x4c, 0x89, 0x72, 0x38,        /* mov [rdx+56],r14       */
    0x4c, 0x89, 0x7a, 0x40,        /* mov [rdx+64],r15       */
  #if !defined(LIBCO_NO_SSE)
    0x0f, 0x29, 0x72, 0x50,        /* movaps [rdx+ 80],xmm6  */
    0x0f, 0x29, 0x7a, 0x60,        /* movaps [rdx+ 96],xmm7  */
    0x44, 0x0f, 0x29, 0x42, 0x70,  /* movaps [rdx+112],xmm8  */
    0x48, 0x83, 0xc2, 0x70,        /* add rdx,112            */
    0x44, 0x0f, 0x29, 0x4a, 0x10,  /* movaps [rdx+ 16],xmm9  */
    0x44, 0x0f, 0x29, 0x52, 0x20,  /* movaps [rdx+ 32],xmm10 */
    0x44, 0x0f, 0x29, 0x5a, 0x30,  /* movaps [rdx+ 48],xmm11 */
    0x44, 0x0f, 0x29, 0x62, 0x40,  /* movaps [rdx+ 64],xmm12 */
    0x44, 0x0f, 0x29, 0x6a, 0x50,  /* movaps [rdx+ 80],xmm13 */
    0x44, 0x0f, 0x29, 0x72, 0x60,  /* movaps [rdx+ 96],xmm14 */
    0x44, 0x0f, 0x29, 0x7a, 0x70,  /* movaps [rdx+112],xmm15 */
  #endif
    0x48, 0x8b, 0x69, 0x08,        /* mov rbp,[rcx+ 8]       */
    0x48, 0x8b, 0x71, 0x10,        /* mov rsi,[rcx+16]       */
    0x48, 0x8b, 0x79, 0x18,        /* mov rdi,[rcx+24]       */
    0x48, 0x8b, 0x59, 0x20,        /* mov rbx,[rcx+32]       */
    0x4c, 0x8b, 0x61, 0x28,        /* mov r12,[rcx+40]       */
    0x4c, 0x8b, 0x69, 0x30,        /* mov r13,[rcx+48]       */
    0x4c, 0x8b, 0x71, 0x38,        /* mov r14,[rcx+56]       */
    0x4c, 0x8b, 0x79, 0x40,        /* mov r15,[rcx+64]       */
  #if !defined(LIBCO_NO_SSE)
    0x0f, 0x28, 0x71, 0x50,        /* movaps xmm6, [rcx+ 80] */
    0x0f, 0x28, 0x79, 0x60,        /* movaps xmm7, [rcx+ 96] */
    0x44, 0x0f, 0x28, 0x41, 0x70,  /* movaps xmm8, [rcx+112] */
    0x48, 0x83, 0xc1, 0x70,        /* add rcx,112            */
    0x44, 0x0f, 0x28, 0x49, 0x10,  /* movaps xmm9, [rcx+ 16] */
    0x44, 0x0f, 0x28, 0x51, 0x20,  /* movaps xmm10,[rcx+ 32] */
    0x44, 0x0f, 0x28, 0x59, 0x30,  /* movaps xmm11,[rcx+ 48] */
    0x44, 0x0f, 0x28, 0x61, 0x40,  /* movaps xmm12,[rcx+ 64] */
    0x44, 0x0f, 0x28, 0x69, 0x50,  /* movaps xmm13,[rcx+ 80] */
    0x44, 0x0f, 0x28, 0x71, 0x60,  /* movaps xmm14,[rcx+ 96] */
    0x44, 0x0f, 0x28, 0x79, 0x70,  /* movaps xmm15,[rcx+112] */
  #endif
    0xff, 0xe0,                    /* jmp rax                */
  };

  #include <windows.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    DWORD old_privileges;
    VirtualProtect((void*)co_swap_function, sizeof co_swap_function, PAGE_EXECUTE_READ, &old_privileges);
    #endif
  }
#else
  /* ABI: SystemV */
  static const unsigned char co_swap_function[4096] = {
    0x48, 0x89, 0x26,        /* mov [rsi],rsp    */
    0x48, 0x8b, 0x27,        /* mov rsp,[rdi]    */
    0x58,                    /* pop rax          */
    0x48, 0x89, 0x6e, 0x08,  /* mov [rsi+ 8],rbp */
    0x48, 0x89, 0x5e, 0x10,  /* mov [rsi+16],rbx */
    0x4c, 0x89, 0x66, 0x18,  /* mov [rsi+24],r12 */
    0x4c, 0x89, 0x6e, 0x20,  /* mov [rsi+32],r13 */
    0x4c, 0x89, 0x76, 0x28,  /* mov [rsi+40],r14 */
    0x4c, 0x89, 0x7e, 0x30,  /* mov [rsi+48],r15 */
    0x48, 0x8b, 0x6f, 0x08,  /* mov rbp,[rdi+ 8] */
    0x48, 0x8b, 0x5f, 0x10,  /* mov rbx,[rdi+16] */
    0x4c, 0x8b, 0x67, 0x18,  /* mov r12,[rdi+24] */
    0x4c, 0x8b, 0x6f, 0x20,  /* mov r13,[rdi+32] */
    0x4c, 0x8b, 0x77, 0x28,  /* mov r14,[rdi+40] */
    0x4c, 0x8b, 0x7f, 0x30,  /* mov r15,[rdi+48] */
    0xff, 0xe0,              /* jmp rax          */
  };

  #include <unistd.h>
  #include <sys/mman.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    unsigned long long addr = (unsigned long long)co_swap_function;
    unsigned long long base = addr - (addr % sysconf(_SC_PAGESIZE));
    unsigned long long size = (addr - base) + sizeof co_swap_function;
    mprotect((void*)base, size, PROT_READ | PROT_EXEC);
    #endif
  }
#endif

static void crash() {
  assert(0);  /* called only if cothread_t entrypoint returns */
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  return co_active_handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size){
  cothread_t handle;
  if(!co_swap) {
    co_init();
    co_swap = (void (*)(cothread_t, cothread_t))co_swap_function;
  }

  if(!co_active_handle) co_active_handle = &co_active_buffer;
  size += 512;  /* allocate additional space for storage */
  size &= ~15;  /* align stack to 16-byte boundary */
  if (out_size) *out_size = size;

  if((handle = (cothread_t)malloc(size))) {
    long long *p = (long long*)((char*)handle + size);  /* seek to top of stack */
    *--p = (long long)crash;                            /* crash if entrypoint returns */
    *--p = (long long)entrypoint;                       /* start of function */
    *(long long*)handle = (long long)p;                 /* stack pointer */
  }

  return handle;
}

void co_delete(cothread_t handle) {
  free(handle);
}

void co_switch(cothread_t handle) {
  register cothread_t co_previous_handle = co_active_handle;
  co_swap(co_active_handle = handle, co_previous_handle);
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #elif defined(__arm__)
    //#include "arm.c"
    #pragma region arm.c
    /*
  libco.arm (2016-09-14)
  author: byuu
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local unsigned long co_active_buffer[64];
static thread_local cothread_t co_active_handle = 0;
static void (*co_swap)(cothread_t, cothread_t) = 0;

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  text_section
#endif
static const unsigned long co_swap_function[1024] = {
  0xe8a16ff0,  /* stmia r1!, {r4-r11,sp,lr} */
  0xe8b0aff0,  /* ldmia r0!, {r4-r11,sp,pc} */
  0xe12fff1e,  /* bx lr                     */
};

static void co_init() {
  #ifdef LIBCO_MPROTECT
  unsigned long addr = (unsigned long)co_swap_function;
  unsigned long base = addr - (addr % sysconf(_SC_PAGESIZE));
  unsigned long size = (addr - base) + sizeof co_swap_function;
  mprotect((void*)base, size, PROT_READ | PROT_EXEC);
  #endif
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  return co_active_handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size) {
  unsigned long* handle = 0;
  if(!co_swap) {
    co_init();
    co_swap = (void (*)(cothread_t, cothread_t))co_swap_function;
  }
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  size += 256;
  size &= ~15;
  if (out_size) *out_size = size;

  if(handle = (unsigned long*)malloc(size)) {
    unsigned long* p = (unsigned long*)((unsigned char*)handle + size);
    handle[8] = (unsigned long)p;
    handle[9] = (unsigned long)entrypoint;
  }

  return handle;
}

void co_delete(cothread_t handle) {
  free(handle);
}

void co_switch(cothread_t handle) {
  cothread_t co_previous_handle = co_active_handle;
  co_swap(co_active_handle = handle, co_previous_handle);
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #elif defined(__aarch64__)
    //#include "aarch64.c"
    #pragma region aarch64.c
    /*
  libco.aarch64 (2017-06-26)
  author: webgeek1234
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef IOS
#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static thread_local uint64_t co_active_buffer[64];
static thread_local cothread_t co_active_handle;

asm (
      ".text\n"
      ".globl co_switch_aarch64\n"
      ".globl _co_switch_aarch64\n"
      "co_switch_aarch64:\n"
      "_co_switch_aarch64:\n"
      "  stp x8,  x9,  [x1]\n"
      "  stp x10, x11, [x1, #16]\n"
      "  stp x12, x13, [x1, #32]\n"
      "  stp x14, x15, [x1, #48]\n"
      "  str x19, [x1, #72]\n"
      "  stp x20, x21, [x1, #80]\n"
      "  stp x22, x23, [x1, #96]\n"
      "  stp x24, x25, [x1, #112]\n"
      "  stp x26, x27, [x1, #128]\n"
      "  stp x28, x29, [x1, #144]\n"
      "  mov x16, sp\n"
      "  stp x16, x30, [x1, #160]\n"

      "  ldp x8,  x9,  [x0]\n"
      "  ldp x10, x11, [x0, #16]\n"
      "  ldp x12, x13, [x0, #32]\n"
      "  ldp x14, x15, [x0, #48]\n"
      "  ldr x19, [x0, #72]\n"
      "  ldp x20, x21, [x0, #80]\n"
      "  ldp x22, x23, [x0, #96]\n"
      "  ldp x24, x25, [x0, #112]\n"
      "  ldp x26, x27, [x0, #128]\n"
      "  ldp x28, x29, [x0, #144]\n"
      "  ldp x16, x17, [x0, #160]\n"
      "  mov sp, x16\n"
      "  br x17\n"
      ".previous\n"
    );

/* ASM */
void co_switch_aarch64(cothread_t handle, cothread_t current);

static void crash(void)
{
   /* Called only if cothread_t entrypoint returns. */
   assert(0);
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size)
{
   size = (size + 1023) & ~1023;
   cothread_t handle = 0;
#if HAVE_POSIX_MEMALIGN >= 1
   if (posix_memalign(&handle, 1024, size + 512) < 0)
      return 0;
#else
   handle = memalign(1024, size + 512);
#endif

   if (!handle)
      return handle;

   uint64_t *ptr = (uint64_t*)handle;
   /* Non-volatiles.  */
   ptr[0]  = 0; /* x8  */
   ptr[1]  = 0; /* x9  */
   ptr[2]  = 0; /* x10 */
   ptr[3]  = 0; /* x11 */
   ptr[4]  = 0; /* x12 */
   ptr[5]  = 0; /* x13 */
   ptr[6]  = 0; /* x14 */
   ptr[7]  = 0; /* x15 */
   ptr[8]  = 0; /* padding */
   ptr[9]  = 0; /* x19 */
   ptr[10] = 0; /* x20 */
   ptr[11] = 0; /* x21 */
   ptr[12] = 0; /* x22 */
   ptr[13] = 0; /* x23 */
   ptr[14] = 0; /* x24 */
   ptr[15] = 0; /* x25 */
   ptr[16] = 0; /* x26 */
   ptr[17] = 0; /* x27 */
   ptr[18] = 0; /* x28 */
   ptr[20] = (uintptr_t)ptr + size + 512 - 16; /* x30, stack pointer */
   ptr[19] = ptr[20]; /* x29, frame pointer */
   ptr[21] = (uintptr_t)entrypoint; /* PC (link register x31 gets saved here). */

   if (out_size) *out_size = size + 512;
   return handle;
}

cothread_t co_active(void)
{
   if (!co_active_handle)
      co_active_handle = co_active_buffer;
   return co_active_handle;
}

void co_delete(cothread_t handle)
{
   free(handle);
}

void co_switch(cothread_t handle)
{
   cothread_t co_previous_handle = co_active();
   co_switch_aarch64(co_active_handle = handle, co_previous_handle);
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #elif defined(_ARCH_PPC)
    //#include "ppc.c"
    #pragma region ppc.c
    /*
  libco.ppc (2016-09-14)
  author: blargg
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if LIBCO_MPROTECT
  #include <unistd.h>
  #include <sys/mman.h>
#endif

/* state format (offsets in 32-bit words)

 +0 pointer to swap code
    rest of function descriptor for entry function
 +8 PC
+10 SP
    special registers
    GPRs
    FPRs
    VRs
    stack
*/

enum { state_size  = 1024 };
enum { above_stack = 2048 };
enum { stack_align = 256  };

static thread_local cothread_t co_active_handle = 0;

/* determine environment */

#define LIBCO_PPC64 (_ARCH_PPC64 || __PPC64__ || __ppc64__ || __powerpc64__)

/* whether function calls are indirect through a descriptor, or are directly to function */
#ifndef LIBCO_PPCDESC
  #if !_CALL_SYSV && (_CALL_AIX || _CALL_AIXDESC || LIBCO_PPC64)
    #define LIBCO_PPCDESC 1
  #endif
#endif

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  text_section
#endif
static const uint32_t libco_ppc_code[1024] = {
  #if LIBCO_PPC64
  0x7d000026,  /* mfcr    r8          */
  0xf8240028,  /* std     r1,40(r4)   */
  0x7d2802a6,  /* mflr    r9          */
  0xf9c40048,  /* std     r14,72(r4)  */
  0xf9e40050,  /* std     r15,80(r4)  */
  0xfa040058,  /* std     r16,88(r4)  */
  0xfa240060,  /* std     r17,96(r4)  */
  0xfa440068,  /* std     r18,104(r4) */
  0xfa640070,  /* std     r19,112(r4) */
  0xfa840078,  /* std     r20,120(r4) */
  0xfaa40080,  /* std     r21,128(r4) */
  0xfac40088,  /* std     r22,136(r4) */
  0xfae40090,  /* std     r23,144(r4) */
  0xfb040098,  /* std     r24,152(r4) */
  0xfb2400a0,  /* std     r25,160(r4) */
  0xfb4400a8,  /* std     r26,168(r4) */
  0xfb6400b0,  /* std     r27,176(r4) */
  0xfb8400b8,  /* std     r28,184(r4) */
  0xfba400c0,  /* std     r29,192(r4) */
  0xfbc400c8,  /* std     r30,200(r4) */
  0xfbe400d0,  /* std     r31,208(r4) */
  0xf9240020,  /* std     r9,32(r4)   */
  0xe8e30020,  /* ld      r7,32(r3)   */
  0xe8230028,  /* ld      r1,40(r3)   */
  0x48000009,  /* bl      1           */
  0x7fe00008,  /* trap                */
  0x91040030, /*1:stw     r8,48(r4)   */
  0x80c30030,  /* lwz     r6,48(r3)   */
  0x7ce903a6,  /* mtctr   r7          */
  0xe9c30048,  /* ld      r14,72(r3)  */
  0xe9e30050,  /* ld      r15,80(r3)  */
  0xea030058,  /* ld      r16,88(r3)  */
  0xea230060,  /* ld      r17,96(r3)  */
  0xea430068,  /* ld      r18,104(r3) */
  0xea630070,  /* ld      r19,112(r3) */
  0xea830078,  /* ld      r20,120(r3) */
  0xeaa30080,  /* ld      r21,128(r3) */
  0xeac30088,  /* ld      r22,136(r3) */
  0xeae30090,  /* ld      r23,144(r3) */
  0xeb030098,  /* ld      r24,152(r3) */
  0xeb2300a0,  /* ld      r25,160(r3) */
  0xeb4300a8,  /* ld      r26,168(r3) */
  0xeb6300b0,  /* ld      r27,176(r3) */
  0xeb8300b8,  /* ld      r28,184(r3) */
  0xeba300c0,  /* ld      r29,192(r3) */
  0xebc300c8,  /* ld      r30,200(r3) */
  0xebe300d0,  /* ld      r31,208(r3) */
  0x7ccff120,  /* mtcr    r6          */
  #else
  0x7d000026,  /* mfcr    r8          */
  0x90240028,  /* stw     r1,40(r4)   */
  0x7d2802a6,  /* mflr    r9          */
  0x91a4003c,  /* stw     r13,60(r4)  */
  0x91c40040,  /* stw     r14,64(r4)  */
  0x91e40044,  /* stw     r15,68(r4)  */
  0x92040048,  /* stw     r16,72(r4)  */
  0x9224004c,  /* stw     r17,76(r4)  */
  0x92440050,  /* stw     r18,80(r4)  */
  0x92640054,  /* stw     r19,84(r4)  */
  0x92840058,  /* stw     r20,88(r4)  */
  0x92a4005c,  /* stw     r21,92(r4)  */
  0x92c40060,  /* stw     r22,96(r4)  */
  0x92e40064,  /* stw     r23,100(r4) */
  0x93040068,  /* stw     r24,104(r4) */
  0x9324006c,  /* stw     r25,108(r4) */
  0x93440070,  /* stw     r26,112(r4) */
  0x93640074,  /* stw     r27,116(r4) */
  0x93840078,  /* stw     r28,120(r4) */
  0x93a4007c,  /* stw     r29,124(r4) */
  0x93c40080,  /* stw     r30,128(r4) */
  0x93e40084,  /* stw     r31,132(r4) */
  0x91240020,  /* stw     r9,32(r4)   */
  0x80e30020,  /* lwz     r7,32(r3)   */
  0x80230028,  /* lwz     r1,40(r3)   */
  0x48000009,  /* bl      1           */
  0x7fe00008,  /* trap                */
  0x91040030, /*1:stw     r8,48(r4)   */
  0x80c30030,  /* lwz     r6,48(r3)   */
  0x7ce903a6,  /* mtctr   r7          */
  0x81a3003c,  /* lwz     r13,60(r3)  */
  0x81c30040,  /* lwz     r14,64(r3)  */
  0x81e30044,  /* lwz     r15,68(r3)  */
  0x82030048,  /* lwz     r16,72(r3)  */
  0x8223004c,  /* lwz     r17,76(r3)  */
  0x82430050,  /* lwz     r18,80(r3)  */
  0x82630054,  /* lwz     r19,84(r3)  */
  0x82830058,  /* lwz     r20,88(r3)  */
  0x82a3005c,  /* lwz     r21,92(r3)  */
  0x82c30060,  /* lwz     r22,96(r3)  */
  0x82e30064,  /* lwz     r23,100(r3) */
  0x83030068,  /* lwz     r24,104(r3) */
  0x8323006c,  /* lwz     r25,108(r3) */
  0x83430070,  /* lwz     r26,112(r3) */
  0x83630074,  /* lwz     r27,116(r3) */
  0x83830078,  /* lwz     r28,120(r3) */
  0x83a3007c,  /* lwz     r29,124(r3) */
  0x83c30080,  /* lwz     r30,128(r3) */
  0x83e30084,  /* lwz     r31,132(r3) */
  0x7ccff120,  /* mtcr    r6 */
  #endif

  #ifndef LIBCO_PPC_NOFP
  0xd9c400e0,  /* stfd    f14,224(r4) */
  0xd9e400e8,  /* stfd    f15,232(r4) */
  0xda0400f0,  /* stfd    f16,240(r4) */
  0xda2400f8,  /* stfd    f17,248(r4) */
  0xda440100,  /* stfd    f18,256(r4) */
  0xda640108,  /* stfd    f19,264(r4) */
  0xda840110,  /* stfd    f20,272(r4) */
  0xdaa40118,  /* stfd    f21,280(r4) */
  0xdac40120,  /* stfd    f22,288(r4) */
  0xdae40128,  /* stfd    f23,296(r4) */
  0xdb040130,  /* stfd    f24,304(r4) */
  0xdb240138,  /* stfd    f25,312(r4) */
  0xdb440140,  /* stfd    f26,320(r4) */
  0xdb640148,  /* stfd    f27,328(r4) */
  0xdb840150,  /* stfd    f28,336(r4) */
  0xdba40158,  /* stfd    f29,344(r4) */
  0xdbc40160,  /* stfd    f30,352(r4) */
  0xdbe40168,  /* stfd    f31,360(r4) */
  0xc9c300e0,  /* lfd     f14,224(r3) */
  0xc9e300e8,  /* lfd     f15,232(r3) */
  0xca0300f0,  /* lfd     f16,240(r3) */
  0xca2300f8,  /* lfd     f17,248(r3) */
  0xca430100,  /* lfd     f18,256(r3) */
  0xca630108,  /* lfd     f19,264(r3) */
  0xca830110,  /* lfd     f20,272(r3) */
  0xcaa30118,  /* lfd     f21,280(r3) */
  0xcac30120,  /* lfd     f22,288(r3) */
  0xcae30128,  /* lfd     f23,296(r3) */
  0xcb030130,  /* lfd     f24,304(r3) */
  0xcb230138,  /* lfd     f25,312(r3) */
  0xcb430140,  /* lfd     f26,320(r3) */
  0xcb630148,  /* lfd     f27,328(r3) */
  0xcb830150,  /* lfd     f28,336(r3) */
  0xcba30158,  /* lfd     f29,344(r3) */
  0xcbc30160,  /* lfd     f30,352(r3) */
  0xcbe30168,  /* lfd     f31,360(r3) */
  #endif

  #ifdef __ALTIVEC__
  0x7ca042a6,  /* mfvrsave r5        */
  0x39040180,  /* addi    r8,r4,384  */
  0x39240190,  /* addi    r9,r4,400  */
  0x70a00fff,  /* andi.   r0,r5,4095 */
  0x90a40034,  /* stw     r5,52(r4)  */
  0x4182005c,  /* beq-    2          */
  0x7e8041ce,  /* stvx    v20,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7ea049ce,  /* stvx    v21,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7ec041ce,  /* stvx    v22,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7ee049ce,  /* stvx    v23,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f0041ce,  /* stvx    v24,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7f2049ce,  /* stvx    v25,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f4041ce,  /* stvx    v26,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7f6049ce,  /* stvx    v27,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f8041ce,  /* stvx    v28,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7fa049ce,  /* stvx    v29,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7fc041ce,  /* stvx    v30,r0,r8  */
  0x7fe049ce,  /* stvx    v31,r0,r9  */
  0x80a30034, /*2:lwz     r5,52(r3)  */
  0x39030180,  /* addi    r8,r3,384  */
  0x39230190,  /* addi    r9,r3,400  */
  0x70a00fff,  /* andi.   r0,r5,4095 */
  0x7ca043a6,  /* mtvrsave r5        */
  0x4d820420,  /* beqctr             */
  0x7e8040ce,  /* lvx     v20,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7ea048ce,  /* lvx     v21,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7ec040ce,  /* lvx     v22,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7ee048ce,  /* lvx     v23,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f0040ce,  /* lvx     v24,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7f2048ce,  /* lvx     v25,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f4040ce,  /* lvx     v26,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7f6048ce,  /* lvx     v27,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7f8040ce,  /* lvx     v28,r0,r8  */
  0x39080020,  /* addi    r8,r8,32   */
  0x7fa048ce,  /* lvx     v29,r0,r9  */
  0x39290020,  /* addi    r9,r9,32   */
  0x7fc040ce,  /* lvx     v30,r0,r8  */
  0x7fe048ce,  /* lvx     v31,r0,r9  */
  #endif

  0x4e800420,  /* bctr */
};

#if LIBCO_PPCDESC
  /* function call goes through indirect descriptor */
  #define CO_SWAP_ASM(x, y) ((void (*)(cothread_t, cothread_t))(uintptr_t)x)(x, y)
#else
  /* function call goes directly to code */
  #define CO_SWAP_ASM(x, y) ((void (*)(cothread_t, cothread_t))(uintptr_t)libco_ppc_code)(x, y)
#endif

static uint32_t* co_create_(unsigned size, uintptr_t entry) {
  (void)entry;

  uint32_t* t = (uint32_t*)malloc(size);

  #if LIBCO_PPCDESC
  if(t) {
    memcpy(t, (void*)entry, sizeof(void*) * 3);  /* copy entry's descriptor */
    *(const void**)t = libco_ppc_code;  /* set function pointer to swap routine */
  }
  #endif

  return t;
}

cothread_t co_create(unsigned int size, void (*entry_)(void)) {
  uintptr_t entry = (uintptr_t)entry_;
  uint32_t* t = 0;

  /* be sure main thread was successfully allocated */
  if(co_active()) {
    size += state_size + above_stack + stack_align;
    t = co_create_(size, entry);
  }

  if(t) {
    uintptr_t sp;
    int shift;

    /* save current registers into new thread, so that any special ones will have proper values when thread is begun */
    CO_SWAP_ASM(t, t);

    #if LIBCO_PPCDESC
    entry = (uintptr_t)*(void**)entry;  /* get real address */
    #endif

    /* put stack near end of block, and align */
    sp = (uintptr_t)t + size - above_stack;
    sp -= sp % stack_align;

    /* on PPC32, we save and restore GPRs as 32 bits. for PPC64, we
       save and restore them as 64 bits, regardless of the size the ABI
       uses. so, we manually write pointers at the proper size. we always
       save and restore at the same address, and since PPC is big-endian,
       we must put the low byte first on PPC32. */

    /* if uintptr_t is 32 bits, >>32 is undefined behavior,
       so we do two shifts and don't have to care how many bits uintptr_t is. */
    #if LIBCO_PPC64
    shift = 16;
    #else
    shift = 0;
    #endif

    /* set up so entry will be called on next swap */
    t[ 8] = (uint32_t)(entry >> shift >> shift);
    t[ 9] = (uint32_t)entry;

    t[10] = (uint32_t)(sp >> shift >> shift);
    t[11] = (uint32_t)sp;
  }

  return t;
}

void co_delete(cothread_t t) {
  free(t);
}

static void co_init_(void) {
  #if LIBCO_MPROTECT
  long page_size = sysconf(_SC_PAGESIZE);
  if(page_size > 0) {
    uintptr_t align = page_size;
    uintptr_t begin = (uintptr_t)libco_ppc_code;
    uintptr_t end   = begin + sizeof libco_ppc_code;

    /* align beginning and end */
    end   += align - 1;
    end   -= end   % align;
    begin -= begin % align;

    mprotect((void*)begin, end - begin, PROT_READ | PROT_EXEC);
  }
  #endif

  co_active_handle = co_create_(state_size, (uintptr_t)&co_switch);
}

cothread_t co_active() {
  if(!co_active_handle) co_init_();

  return co_active_handle;
}

void co_switch(cothread_t t) {
  cothread_t old = co_active_handle;
  co_active_handle = t;

  CO_SWAP_ASM(t, old);
}

    #pragma endregion
  #elif defined(_WIN32)
    //#include "fiber.c"
    #pragma region fiber.c
    /*
  libco.win (2008-01-28)
  authors: Nach, byuu
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local cothread_t co_active_ = 0;

static void __stdcall co_thunk(void* coentry) {
  ((void (*)(void))coentry)();
}

cothread_t co_active() {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  return co_active_;
}

cothread_t co_create(unsigned int heapsize, void (*coentry)(void),
                     size_t *out_size) {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  if (out_size) *out_size = heapsize;
  return (cothread_t)CreateFiber(heapsize, co_thunk, (void*)coentry);
}

void co_delete(cothread_t cothread) {
  DeleteFiber(cothread);
}

void co_switch(cothread_t cothread) {
  co_active_ = cothread;
  SwitchToFiber(cothread);
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #else
    //#include "sjlj.c"
    #pragma region sjlj.c
    /*
  libco.sjlj (2008-01-28)
  author: Nach
  license: public domain
*/

/*
  note this was designed for UNIX systems. Based on ideas expressed in a paper by Ralf Engelschall.
  for SJLJ on other systems, one would want to rewrite springboard() and co_create() and hack the jmb_buf stack pointer.
*/

#define LIBCO_C
//#include "libco.h"

#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  sigjmp_buf context;
  void (*coentry)(void);
  void* stack;
} cothread_struct;

static thread_local cothread_struct co_primary;
static thread_local cothread_struct* creating;
static thread_local cothread_struct* co_running = 0;

static void springboard(int ignored) {
  if(sigsetjmp(creating->context, 0)) {
    co_running->coentry();
  }
}

cothread_t co_active() {
  if(!co_running) co_running = &co_primary;
  return (cothread_t)co_running;
}

cothread_t co_create(unsigned int size, void (*coentry)(void),
                     size_t *out_size) {
  if(!co_running) co_running = &co_primary;

  cothread_struct *thread = (cothread_struct*)malloc(sizeof(cothread_struct));
  if(thread) {
    struct sigaction handler;
    struct sigaction old_handler;

    stack_t stack;
    stack_t old_stack;

    thread->coentry = thread->stack = 0;

    stack.ss_flags = 0;
    stack.ss_size = size;
    thread->stack = stack.ss_sp = malloc(size);
    if(stack.ss_sp && !sigaltstack(&stack, &old_stack)) {
      handler.sa_handler = springboard;
      handler.sa_flags = SA_ONSTACK;
      sigemptyset(&handler.sa_mask);
      creating = thread;

      if(!sigaction(SIGUSR1, &handler, &old_handler)) {
        if(!raise(SIGUSR1)) {
          thread->coentry = coentry;
        }
        sigaltstack(&old_stack, 0);
        sigaction(SIGUSR1, &old_handler, 0);
      }
    }

    if(thread->coentry != coentry) {
      co_delete(thread);
      thread = 0;
    }
  }

  if (out_size) *out_size = size;
  return (cothread_t)thread;
}

void co_delete(cothread_t cothread) {
  if(cothread) {
    if(((cothread_struct*)cothread)->stack) {
      free(((cothread_struct*)cothread)->stack);
    }
    free(cothread);
  }
}

void co_switch(cothread_t cothread) {
  if(!sigsetjmp(co_running->context, 0)) {
    co_running = (cothread_struct*)cothread;
    siglongjmp(co_running->context, 1);
  }
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #endif
#elif defined(_MSC_VER)
  #if defined(_M_IX86)
    //#include "x86.c"
     #pragma region x86.c
/*
  libco.x86 (2016-09-14)
  author: byuu
  license: public domain
*/

#define LIBCO_C
////#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#include <assert.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__) || defined(__GNUC__)
  #define fastcall __attribute__((fastcall))
#elif defined(_MSC_VER)
  #define fastcall __fastcall
#else
  #error "libco: please define fastcall macro"
#endif

static thread_local long co_active_buffer[64];
static thread_local cothread_t co_active_handle = 0;
static void (fastcall *co_swap)(cothread_t, cothread_t) = 0;

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  text_section
#endif
/* ABI: fastcall */
static const unsigned char co_swap_function[4096] = {
  0x89, 0x22,        /* mov [edx],esp    */
  0x8b, 0x21,        /* mov esp,[ecx]    */
  0x58,              /* pop eax          */
  0x89, 0x6a, 0x04,  /* mov [edx+ 4],ebp */
  0x89, 0x72, 0x08,  /* mov [edx+ 8],esi */
  0x89, 0x7a, 0x0c,  /* mov [edx+12],edi */
  0x89, 0x5a, 0x10,  /* mov [edx+16],ebx */
  0x8b, 0x69, 0x04,  /* mov ebp,[ecx+ 4] */
  0x8b, 0x71, 0x08,  /* mov esi,[ecx+ 8] */
  0x8b, 0x79, 0x0c,  /* mov edi,[ecx+12] */
  0x8b, 0x59, 0x10,  /* mov ebx,[ecx+16] */
  0xff, 0xe0,        /* jmp eax          */
};

#ifdef _WIN32
  #include <windows.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    DWORD old_privileges;
    VirtualProtect((void*)co_swap_function, sizeof co_swap_function, PAGE_EXECUTE_READ, &old_privileges);
    #endif
  }
#else
  #include <unistd.h>
  #include <sys/mman.h>

  static void co_init() {
    #ifdef LIBCO_MPROTECT
    unsigned long addr = (unsigned long)co_swap_function;
    unsigned long base = addr - (addr % sysconf(_SC_PAGESIZE));
    unsigned long size = (addr - base) + sizeof co_swap_function;
    mprotect((void*)base, size, PROT_READ | PROT_EXEC);
    #endif
  }
#endif

static void crash() {
  assert(0);  /* called only if cothread_t entrypoint returns */
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  return co_active_handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size) {
  cothread_t handle;
  if(!co_swap) {
    co_init();
    co_swap = (void (fastcall*)(cothread_t, cothread_t))co_swap_function;
  }
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  size += 256;  /* allocate additional space for storage */
  size &= ~15;  /* align stack to 16-byte boundary */
  if (out_size) *out_size = size;

  if(handle = (cothread_t)malloc(size)) {
    long *p = (long*)((char*)handle + size);  /* seek to top of stack */
    *--p = (long)crash;                       /* crash if entrypoint returns */
    *--p = (long)entrypoint;                  /* start of function */
    *(long*)handle = (long)p;                 /* stack pointer */
  }

  return handle;
}

void co_delete(cothread_t handle) {
  free(handle);
}

void co_switch(cothread_t handle) {
  register cothread_t co_previous_handle = co_active_handle;
  co_swap(co_active_handle = handle, co_previous_handle);
}

#ifdef __cplusplus
}
#endif

#pragma endregion

// Commented out due to SIGSEGV bug
//  #elif defined(_M_AMD64)
//    #include "amd64.c"
  #else
    //#include "fiber.c"
      #pragma region fiber.c
    /*
  libco.win (2008-01-28)
  authors: Nach, byuu
  license: public domain
*/

#define LIBCO_C
//#include "libco.h"
//#include "settings.h"
#pragma region settings.h
#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif

#pragma endregion

#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local cothread_t co_active_ = 0;

static void __stdcall co_thunk(void* coentry) {
  ((void (*)(void))coentry)();
}

cothread_t co_active() {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  return co_active_;
}

cothread_t co_create(unsigned int heapsize, void (*coentry)(void),
                     size_t *out_size) {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  if (out_size) *out_size = heapsize;
  return (cothread_t)CreateFiber(heapsize, co_thunk, (void*)coentry);
}

void co_delete(cothread_t cothread) {
  DeleteFiber(cothread);
}

void co_switch(cothread_t cothread) {
  co_active_ = cothread;
  SwitchToFiber(cothread);
}

#ifdef __cplusplus
}
#endif

    #pragma endregion
  #endif
#else
  #error "libco: unsupported processor, compiler or operating system"
#endif

#pragma endregion

#endif

/*
LICENSE

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
*/