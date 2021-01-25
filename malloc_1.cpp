
#include <unistd.h>
#include <errno.h>
#define MAX_INT_SIZE 100000000

void* smalloc_ (size_t size) {
    if (size == 0 || size > MAX_INT_SIZE) return NULL;
    void *ptr = sbrk(size);
    if (errno == ENOMEM) return NULL;
    return ptr;
}