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