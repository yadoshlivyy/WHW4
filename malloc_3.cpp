#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <sys/mman.h>

#define MAX_INT_SIZE 100000000
#define NUM_OF_NUMS_DATA 5
#define DELTA 128
#define VERY_BIG_SIZE 128000

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
    void *AllocateNewSmallBlock(size_t size, int *status)
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
     * merges two neigborhood Chunks of memory into bigger one and updates
     * all nums accordingly
     * @param first -pointer to metadata of left node
     * @param next -pointer to metadata to right node
     */
    void mergeNodes(MallocMetadata *first, MallocMetadata *next)
    {
        nums[ALLOC_BLOCKS]--;
        nums[FREE_BLOCKS]--;
        nums[FREE_BYTES] += _size_meta_data();
        nums[ALLOC_BYTES] += _size_meta_data();
        nums[META_BYTES] -= _size_meta_data();
        first->next = next->next;
        first->block_size += next->block_size + _size_meta_data();
        if (next->next)
            next->next->prev = first;
        else
        {
            tail = first;
        }
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
        if (meta->is_free == true)
            return;
        meta->is_free = true;
        if (meta->block_size >= VERY_BIG_SIZE)
        {
            nums[ALLOC_BLOCKS]--;
            nums[ALLOC_BYTES] -= meta->block_size;
            nums[META_BYTES] -= _size_meta_data();
            munmap(meta, meta->block_size + _size_meta_data());
            return;
        }
        nums[FREE_BLOCKS]++;
        nums[FREE_BYTES] += meta->block_size;
        if (meta->next && meta->next->is_free)
        {
            this->mergeNodes(meta, meta->next);
        }
        if (meta->prev && meta->prev->is_free)
        {
            this->mergeNodes(meta->prev, meta);
        }
    }
    /**
   * checks if last allocated element (with biggest adress is free
   * @return
   */
    bool lastUnallocated()
    {
        if (tail == NULL)
        {
            return false;
        }
        return tail->is_free;
    }
    /**
 * function that resizes last element(in case of last element is free) and updates num fields accordingly
 * @param size new size of element
 * @param status
 * @param free_bytes_increment
 */
    void resizeLastChunk(size_t size, int *status, bool free_bytes_increment)
    {
        int delta = size - (tail->block_size);
        if (sbrk(delta) == (void *)-1)
        {
            if (status)
                *status = -1;
            return;
        }
        tail->block_size += delta;
        if (free_bytes_increment)
        {
            nums[FREE_BYTES] += delta;
            nums[ALLOC_BYTES] += delta;
        }
    }
    /**
     * function that try to share current chunk in case if its possibly by defined rules
     * @param pointer
     * @param size
     */
    void tryToShare(void *pointer, size_t size)
    {
        MallocMetadata *metadata = (MallocMetadata *)(((char *)pointer) - _size_meta_data());
        int metastruct_size = _size_meta_data();
        int delta = (metadata->block_size - size - metastruct_size);
        if (delta >= DELTA)
        {
            nums[ALLOC_BLOCKS]++;
            nums[FREE_BLOCKS]++;
            nums[FREE_BYTES] += delta;
            nums[ALLOC_BYTES] -= metastruct_size;
            nums[META_BYTES] += metastruct_size;

            MallocMetadata *new_block_metadata = (MallocMetadata *)(((char *)pointer) + size);
            *new_block_metadata = MallocMetadata(delta);
            new_block_metadata->is_free = true;
            metadata->block_size = size;

            new_block_metadata->next = metadata->next;
            new_block_metadata->prev = metadata;
            metadata->next = new_block_metadata;

            if (metadata == tail)
            {
                tail = new_block_metadata;
            }
            else
            {
                new_block_metadata->next->prev = new_block_metadata;
            }
        }
        return;
    }
    /**
 *
 * @return elements with highest adress
 */
    MallocMetadata *getLast()
    {
        return tail;
    }
    /**
 * Allocate big block of data and updates sizes accordingly
 * @param size
 * @return
 */
    void *AllocateNewBigBlock(size_t size)
    {
        void *ptr = mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED)
            return NULL;
        MallocMetadata *meta = (MallocMetadata *)ptr;
        *meta = MallocMetadata(size);
        nums[ALLOC_BLOCKS]++;
        nums[ALLOC_BYTES] += size;
        nums[META_BYTES] += _size_meta_data();
        return (void *)(((char *)meta) + _size_meta_data());
    }
};

MallocList m_list;

void *smalloc(size_t size)
{
    //TODO if really big block...
    void *ptr = NULL;
    int status = 0;
    if (size == 0 || size > MAX_INT_SIZE)
        return NULL;
    if (size >= VERY_BIG_SIZE)
    {
        ptr = m_list.AllocateNewBigBlock(size);
        return ptr;
    }
    ptr = m_list.getFreeBlockBySize(size);
    //    if(ptr) return ptr;

    if (ptr == NULL && m_list.lastUnallocated())
    {
        m_list.resizeLastChunk(size, &status, true);
        if (status == -1)
            return NULL;
        else
        {
            return m_list.getFreeBlockBySize(size);
        }
    }
    if (ptr != NULL)
    {
        m_list.tryToShare(ptr, size);
        return ptr;
    }

    ptr = m_list.AllocateNewSmallBlock(size, &status);
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
    //TODO very big size implementation
    if (size == 0 || size > MAX_INT_SIZE)
        return NULL;
    if (!oldp)
    {
        return smalloc(size);
    }
    MallocMetadata *meta = (MallocMetadata *)(((char *)oldp) - _size_meta_data());
    if (size <= meta->block_size)
    {
        if (meta->block_size >= VERY_BIG_SIZE)
        {
            void *block_ptr = smalloc(size);
            if (!block_ptr)
                return NULL;
            memcpy(block_ptr, oldp, size);
            sfree(oldp);
            return block_ptr;
        }
        else
        {
            m_list.tryToShare(oldp, size);
            return oldp;
        }
    }
    if (size > meta->block_size)
    {
        int status = 0;
        if (meta == m_list.getLast())
        { //if meta is tail
            m_list.nums[ALLOC_BYTES] += size - meta->block_size;
            m_list.resizeLastChunk(size, &status, false);
            if (status == -1)
                return NULL;
            else
            {
                return oldp;
            }
        }
        else
        {
            bool next_available = meta->next && meta->next->is_free;
            bool prev_available = meta->prev && meta->prev->is_free;
            bool booth_available = next_available && prev_available;
            bool merge_with_next =
                next_available && (meta->next->block_size + meta->block_size + _size_meta_data() >= size);
            bool merge_with_prev =
                prev_available && (meta->prev->block_size + meta->block_size + _size_meta_data() >= size);
            bool merge_with_both = booth_available &&
                                   (meta->prev->block_size + meta->block_size + meta->next->block_size +
                                        (2 * _size_meta_data()) >=
                                    size);
            if (merge_with_next)
            {
                m_list.nums[FREE_BYTES] -= (meta->next->block_size + _size_meta_data());
                m_list.mergeNodes(meta, meta->next);
                m_list.tryToShare(oldp, size);
                return oldp;
            }
            if (merge_with_prev)
            {
                void *previous_data_adr = (void *)(((char *)meta->prev) + _size_meta_data());
                m_list.nums[FREE_BYTES] -= (meta->prev->block_size + _size_meta_data());
                m_list.mergeNodes(meta->prev, meta);
                meta->prev->is_free = false;
                memcpy(previous_data_adr, oldp, meta->block_size);
                m_list.tryToShare(previous_data_adr, size);
                return previous_data_adr;
            }
            if (merge_with_both)
            {
                void *previous_data_adr = (void *)(((char *)meta->prev) + _size_meta_data());
                m_list.nums[FREE_BYTES] -= (meta->next->block_size + _size_meta_data());
                m_list.nums[FREE_BYTES] -= (meta->prev->block_size + _size_meta_data());
                meta->prev->is_free = false;
                m_list.mergeNodes(meta, meta->next);
                m_list.mergeNodes(meta->prev, meta);
                memcpy(previous_data_adr, oldp, meta->block_size);
                m_list.tryToShare(previous_data_adr, size);
                return previous_data_adr;
            }
        }
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