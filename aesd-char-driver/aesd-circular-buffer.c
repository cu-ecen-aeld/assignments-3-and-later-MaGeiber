/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    uint8_t i;

    // null checks
    if( buffer == NULL || entry_offset_byte_rtn == NULL)
    {
        return NULL;
    }

    // starting at the out_offs, traverse the the max buffer locations
    for(i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        uint8_t check_location;

        // if we are past the bounds, wrap around
        if((i + buffer->out_offs) >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            check_location = ((i + buffer->out_offs) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
        }
        // otherwise, the location to check is based off the out offset
        else
        {
            check_location = i + buffer->out_offs;
        }
        
        // if the number of bytes in the entry is larger, our character is here
        if(buffer->entry[check_location].size > char_offset)
        {
            *entry_offset_byte_rtn = char_offset;
            return &buffer->entry[check_location];
        }
        // otherwise, keep looking, subtracting the size from our search offset
        else
        {
            char_offset -= buffer->entry[check_location].size;
        }
    }
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // null check
    if(buffer == NULL || add_entry == NULL)
    {
        return;
    }

    // overwrite current entry(lifetime not managed here, see description!), move in offset
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // check if the buffer was full, increment out offset
    if(buffer->full)
    {
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // buffer is full if the offsets are the same
    buffer->full = (buffer->in_offs == buffer->out_offs) ? true : false;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

/**
* Gets the total size of the circular buffer described by @param buffer
*/
size_t aesd_circular_buffer_get_total_size(struct aesd_circular_buffer *buffer)
{
    uint8_t i;
    size_t total_size = 0;

    for(i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        total_size += buffer->entry[i].size;
    }
    return total_size;
}

/* Checks if the write command and offset given are valid for our current circular buffer */
bool aesd_circular_buffer_is_write_cmd_valid(struct aesd_circular_buffer *buffer, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    return (write_cmd < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
           && (buffer->entry[write_cmd].buffptr != NULL)
           && (buffer->entry[write_cmd].size > write_cmd_offset);
}

/* 
* Calculate the offset based on a given write command and write command offset. 
* Note: This assumes we have already checked for validity!
*/
unsigned long aesd_circular_buffer_get_offset_from_write_cmd(struct aesd_circular_buffer *buffer, unsigned long write_cmd, unsigned long write_cmd_offset)
{
    uint8_t i;
    unsigned long offset = 0;

    for(i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        if(i == write_cmd)
        {
            offset += write_cmd_offset;
            break;
        }
        offset += buffer->entry[i].size;
    }
    return offset;
}