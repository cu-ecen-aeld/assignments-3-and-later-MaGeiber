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

    aesd_circular_buffer_init(&dev->circ_buffer);
    mutex_init(&dev->lock);

    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    uint8_t index;
    struct aesd_buffer_entry *entry;

    PDEBUG("release");

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    // free memory used by circular buffer
    AESD_CIRCULAR_BUFFER_FOREACH(entry,&dev->circ_buffer,index)
    {
        kfree(entry->buffptr);
    }
    
    // destroy mutex
    mutex_destroy(&dev->lock);
    
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

    // if more bytes were requested than are in the entry, read out the requested and update f_pos
    if(bytes_in_entry > count)
    {
        bytes_to_copy = count;
        *f_pos += count;
    }
    else
    {
        bytes_to_copy = bytes_in_entry;
        *f_pos += bytes_in_entry;
    }

    // copy data to user space
    copy_user_return = copy_to_user(buf, read_entry->buffptr + entry_offset_byte, bytes_to_copy);
    if(copy_user_return)
    {
        retval = -EFAULT;
        goto release_mutex;
    }

    // update return value to number of bytes read
    retval = bytes_to_copy;

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
        return -EFAULT;
    }

    // copy data to kernel space
    //copy_from_user()

    // check for newline

    // add entry to circular buffer
    // aesd_circular_buffer_add_entry()

    // free any allocated memory
    free_mem:

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

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
