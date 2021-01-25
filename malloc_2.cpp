#include <unistd.h>
#include <errno.h>
#include <cstring>

#define MAX_INT_SIZE 100000000
#define NUM_OF_NUMS_DATA 5

enum
{
    FREE_BLOCKS,
    FREE_BYTES,
    ALLOC_BLOCKS,
    ALLOC_BYTES,
    META_BYTES
};
size_t _size_meta_data();
class MallocMetadata
{
public:
    size_t block_size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
    MallocMetadata(size_t size) : block_size(size), is_free(false), next(NULL), prev(NULL) {}
};

class MallocList
{
    MallocMetadata *head;
    MallocMetadata *tail;

public:
    int nums[NUM_OF_NUMS_DATA];
    MallocList() : head(NULL), tail(NULL)
    {
        for (int i = 0; i < NUM_OF_NUMS_DATA; i++)
            nums[i] = 0;
    }
    /**
     * searches for a freed (previously allocated) block that can fit size. If found returns the block, while setting
     * the block as "not free" and sets nums array accordingly (num of free blocks, free bytes..)
     * this function doesnt allocates new block if non is found
     * @param size
     * @return block ptr if found, NULL else
     */
    void *getFreeBlockBySize(size_t size)
    {
        MallocMetadata *it = head;
        while (it != NULL)
        {
            if (it->is_free && size <= it->block_size)
                break;
            it = it->next;
        }
        if (!it)
            return NULL;
        it->is_free = false;
        nums[FREE_BLOCKS]--;
        nums[FREE_BYTES] -= it->block_size;
        return (void *)(((char *)it) + _size_meta_data());
    }
    /**
     * allocates new block+metadata and adds it to global list, updates nums array accordingly
     * @param size
     * @param status
     * @return ptr to new block upon success, else Null
     */
    void *AllocateNewBlock(size_t size, int *status)
    {
        if (size == 0 || size > MAX_INT_SIZE)
        {
            if (status)
                *status = -1;
            return NULL;
        }
        MallocMetadata *meta = (MallocMetadata *)sbrk(_size_meta_data());
        if (meta == (void *)-1)
        {
            if (status)
                *status = -1;
            return NULL;
        }
        void *block_ptr = sbrk(size);
        if (block_ptr == (void *)-1)
        {
            if (status)
                *status = -1;
            sbrk(-_size_meta_data());
            return NULL;
        }
        *meta = MallocMetadata(size);
        if (!head)
            head = meta;
        if (!tail)
            tail = meta;
        else
        {
            meta->prev = tail;
            tail->next = meta;
            tail = meta;
        }
        nums[ALLOC_BLOCKS]++;
        nums[ALLOC_BYTES] += size;
        nums[META_BYTES] += _size_meta_data();
        return block_ptr;
    }
    /**
     * frees given ptr, doesnt remove block, just sets is as free, updates nums array accordingly.
     * @param ptr
     */
    void freeBlock(void *ptr)
    {
        if (!ptr)
            return;
        MallocMetadata *meta;
        meta = (MallocMetadata *)(((char *)ptr) - _size_meta_data());
        meta->is_free = true;
        nums[FREE_BLOCKS]++;
        nums[FREE_BYTES] += meta->block_size;
    }
};

MallocList m_list;

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_INT_SIZE)
        return NULL;
    void *ptr = m_list.getFreeBlockBySize(size);
    if (ptr)
        return ptr;
    int status = 0;
    ptr = m_list.AllocateNewBlock(size, &status);
    if (status == -1)
        return NULL;
    return ptr;
}

void *scalloc(size_t num, size_t size)
{
    void *ptr = smalloc(num * size);
    if (!ptr)
        return ptr;
    memset(ptr, char(0), num *size);
    return ptr;
}

void sfree(void *p)
{
    m_list.freeBlock(p);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_INT_SIZE)
        return NULL;
    if (!oldp)
    {
        return smalloc(size);
    }
    MallocMetadata *meta = (MallocMetadata *)(((char *)oldp) - _size_meta_data());
    if (size <= meta->block_size)
    {
        //meta->used=size;
        return oldp;
    }
    void *block_ptr = smalloc(size);
    if (!block_ptr)
        return NULL;
    memcpy(block_ptr, oldp, meta->block_size);
    sfree(oldp);
    return block_ptr;
}

size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}

size_t _num_free_blocks()
{
    return m_list.nums[FREE_BLOCKS];
}

size_t _num_free_bytes()
{
    return m_list.nums[FREE_BYTES];
}

size_t _num_allocated_blocks()
{
    return m_list.nums[ALLOC_BLOCKS];
}

size_t _num_allocated_bytes()
{
    return m_list.nums[ALLOC_BYTES];
}

size_t _num_meta_data_bytes()
{
    return m_list.nums[META_BYTES];
}