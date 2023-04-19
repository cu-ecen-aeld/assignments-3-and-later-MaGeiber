/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Matt Geib");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_buffer_entry *read_entry;
    int mutex_ret;
    size_t entry_offset_byte;
    unsigned long copy_user_return;
    unsigned long bytes_in_entry;
    unsigned long bytes_to_copy;
    
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    // lock mutex before doing anything
    mutex_ret = mutex_lock_interruptible(&dev->lock);
    if(mutex_ret != 0)
    {
        // couldn't lock the mutex, something happened, return a fault
        return -EFAULT;
    }

    // get the node from the buffer based on the given position
    read_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circ_buffer, *f_pos, &entry_offset_byte);

    if(read_entry == NULL)
    {
        *f_pos = 0;
        goto release_mutex;
    }

    // determine how much to copy to user buffer
    bytes_in_entry = read_entry->size - entry_offset_byte;

    // if more bytes were in the entry than the requested count, read out the requested number of bytes.
    // otherwise, only read out the bytes in the entry
    if(bytes_in_entry > count)
    {
        bytes_to_copy = count;
    }
    else
    {
        bytes_to_copy = bytes_in_entry;
    }

    // copy data to user space
    copy_user_return = copy_to_user(buf, read_entry->buffptr + entry_offset_byte, bytes_to_copy);

    // update return value to number of bytes read, which would be: number of bytes to copy - bytes that did not copy to user space
    retval = bytes_to_copy - copy_user_return;

    // update fpos based on the amount of bytes actually copied to user space
    *f_pos += retval;

    // release mutex, always
    release_mutex:
        mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    int mutex_ret;
    size_t bytes_not_copied_from_user;
    size_t i;
    bool newline_found;
    struct aesd_buffer_entry temp_buffer_entry;

    struct aesd_dev *dev = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    // lock mutex
    mutex_ret = mutex_lock_interruptible(&dev->lock);
    if(mutex_ret != 0)
    {
        // couldn't lock the mutex, something happened, return a fault
        PDEBUG("Failure to lock mutex in aesd_write");
        retval = -EFAULT;
        goto release_mutex;
    }

    // attempt to allocate enough buffer space for data, if the last command didn't finish, get more memory
    dev->kernel_buffer = krealloc(dev->kernel_buffer, dev->kernel_buffer_size + count, GFP_KERNEL);
    
    if(dev->kernel_buffer == NULL)
    {
        PDEBUG("Failure to allocate enough memory in aesd_write");
        retval = -ENOMEM;
        goto release_mutex;
    }

    // copy data to kernel space
    bytes_not_copied_from_user = copy_from_user(dev->kernel_buffer + dev->kernel_buffer_size, buf, count);
    retval = count - bytes_not_copied_from_user;

    // update buffer size
    dev->kernel_buffer_size += retval;

    // check the current buffer for a newline
    newline_found = false;
    for(i = 0; i < dev->kernel_buffer_size; i++)
    {
        if(dev->kernel_buffer[i] == '\n')
        {
            PDEBUG("Found newline in command");
            newline_found = true;
        }
    }

    // add entry to circular buffer if the newline was found, otherwise release mutex and move on
    if(newline_found)
    {
        PDEBUG("Adding entry to circular buffer, length %zu", i);
        // need to free memory of the last entry if the buffer is full and we are adding
        if(dev->circ_buffer.full)
        {
            PDEBUG("Buffer was full, freeing oldest entry");
            kfree(dev->circ_buffer.entry[dev->circ_buffer.out_offs].buffptr);
        }
        temp_buffer_entry.buffptr = dev->kernel_buffer;
        temp_buffer_entry.size = i;
        aesd_circular_buffer_add_entry(&dev->circ_buffer, &temp_buffer_entry);
        dev->kernel_buffer_size = 0;
        dev->kernel_buffer = NULL;
    }

    // release mutex, always
    release_mutex:
        mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.circ_buffer);
    mutex_init(&aesd_device.lock);
    aesd_device.kernel_buffer = NULL;
    aesd_device.kernel_buffer_size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    // free memory used by circular buffer
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circ_buffer, index)
    {
        kfree(entry->buffptr);
    }
    
    // destroy mutex
    mutex_destroy(&aesd_device.lock);

    kfree(aesd_device.kernel_buffer);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
