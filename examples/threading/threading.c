#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // initialize variable for thread completion
    thread_func_args->thread_complete_success = false;

    // sleep
    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    // lock mutex
    pthread_mutex_lock(thread_func_args->mutex);

    // sleep
    usleep(thread_func_args->wait_to_release_ms * 1000);

    // unlock mutex
    pthread_mutex_unlock(thread_func_args->mutex);

    // set thread completion true
    thread_func_args->thread_complete_success = true;

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    int create_return;

    // allocate struct memory
    struct thread_data * data = malloc(sizeof(struct thread_data));

    // setup arguments
    data->mutex = mutex;
    data->wait_to_obtain_ms = wait_to_obtain_ms;
    data->wait_to_release_ms = wait_to_release_ms;

    // create thread
    create_return = pthread_create(thread, NULL, threadfunc, data);

    // check the return value from thread creation and return status
    if(create_return == 0)
    {
        return true;
    }

    return false;
}

