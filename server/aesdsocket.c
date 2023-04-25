#include <arpa/inet.h>
#include "../aesd-char-driver/aesd_ioctl.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define USE_AESD_CHAR_DEVICE 1

#define SOCK_PORT "9000"
#define CONN_FILE "/var/tmp/aesdsocketdata"
#define AESD_DEVICE "/dev/aesdchar"
#define BUFFER_SIZE 1024
#define IOC_CMD "AESDCHAR_IOCSEEKTO:"

static bool graceful_exit = false;
static pthread_mutex_t file_mutex;
FILE * fp;

struct socket_thread_args
{
    pthread_t thread_id;
    int socket_handle;
    int connected_handle;
    FILE * file_pointer;
    int done_flag;
    pthread_mutex_t * file_mutex;
    SLIST_ENTRY(socket_thread_args) thread_entries;
};

static void signal_handler(int signal_number);
static void cleanup(FILE * file_pointer, int socket_handle, int connected_handle, int exit_status);
static void * socket_thread(void * args);
static void timer_signal();

SLIST_HEAD(socket_list_head, socket_thread_args);

int main(int argc, char *argv[])
{
    fp = NULL;
    int socket_handle;
    int bind_return;
    int listen_return;
    struct sockaddr connected_addr;
    int connected_handle;
    ssize_t bytes_received;
    size_t buffer_bytes_used;
    size_t buffer_bytes_remaining;
    char buffer[BUFFER_SIZE];
    struct sigaction sig_action;
    char client_address[INET_ADDRSTRLEN];
    pid_t proc_id;

    struct socket_list_head head;
    struct socket_thread_args * temp_entry;
    SLIST_INIT(&head);
    pthread_mutex_init(&file_mutex, NULL);

    // open the syslog
    openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);

    // register the signal handler for both signals
    memset(&sig_action, 0, sizeof(struct sigaction));
    sig_action.sa_handler = signal_handler;
    if( sigaction(SIGTERM, &sig_action, NULL) != 0)
    {
        syslog(LOG_ERR, "Failed to register SIGTERM signal!");
    }
    if( sigaction(SIGINT, &sig_action, NULL) != 0)
    {
        syslog(LOG_ERR, "Failed to register SIGINT signal!");
    }

    // end socket loop after sigint or sigterm handler
    while(!graceful_exit)
    {
        // open a stream socket, bind to port 9000, return -1 if socket connection steps fail
        struct addrinfo hint;
        struct addrinfo *returned_addr_info;
        int set_socket_option = 1;
        socklen_t sockaddr_size = sizeof(connected_addr);
        memset(&hint, 0, sizeof(struct addrinfo));
        hint.ai_flags = AI_PASSIVE;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_family = AF_INET;

        // open the file to append to
        if(USE_AESD_CHAR_DEVICE != 1)
        {
            fp = fopen(CONN_FILE, "a+");
            if(fp == NULL)
            {
                // failure to open file for appending
                syslog(LOG_ERR, "Failed to open the file for appending!");
                cleanup(fp, socket_handle, connected_handle, -1);
            }
        }

        int get_addr_return = getaddrinfo(NULL, SOCK_PORT, &hint, &returned_addr_info);
        if(get_addr_return != 0)
        {
            // failed to get bind information
            syslog(LOG_ERR, "Failure during socket setup!");
        }

        // get socket handle
        socket_handle = socket(returned_addr_info->ai_family, returned_addr_info->ai_socktype, returned_addr_info->ai_protocol);
        if(socket_handle == -1)
        {
            // failed to create handle, return
            //fprintf(stdout, "FAILED TO GET SOCKET HANDLE!\n");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        // allow address reuse
        setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &set_socket_option, sizeof(set_socket_option));

        // bind
        bind_return = bind(socket_handle, returned_addr_info->ai_addr, returned_addr_info->ai_addrlen);
        if(bind_return != 0)
        {
            // failed to bind, return
            //fprintf(stdout, "FAILED TO BIND! %d error: %d\n", bind_return, errno);
            //cleanup(fp, socket_handle, connected_handle, -1);
        }

        if(argc == 2)
        {
            if(strcmp(argv[1], "-d") == 0)
            {
                //fprintf(stdout, "Daemon Mode!!!\n");
                proc_id = fork();
                if(proc_id < 0)
                {
                    syslog(LOG_ERR, "Failed to fork a child daemon!");
                    cleanup(fp, socket_handle, connected_handle, -1);
                }
                else if(proc_id != 0)
                {
                    // parent, exit
                    exit(0);
                }
                int status;
                status = setsid();
                status = chdir("/");
                open("/dev/null", O_RDWR);
                dup(0);
                dup(0);
            }
        }

        // register alarm signal handler if not using aesdchar device
        if(USE_AESD_CHAR_DEVICE != 1)
        {
            struct itimerval timestamp_itimer;
            timestamp_itimer.it_value.tv_sec = 10;
            timestamp_itimer.it_value.tv_usec = 0;
            timestamp_itimer.it_interval.tv_sec = 10;
            timestamp_itimer.it_interval.tv_usec = 0;
            setitimer(ITIMER_REAL, &timestamp_itimer, NULL);
            signal(SIGALRM, timer_signal);
        }

        // free the malloc'd memory
        freeaddrinfo(returned_addr_info);

        // listen
        listen_return = listen(socket_handle, SOMAXCONN);
        if(listen_return != 0)
        {
            // failure from listen, return
            //fprintf(stdout, "FAILED TO LISTEN!\n");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        while(!graceful_exit)
        {
            // accept connection
            connected_handle = accept(socket_handle, &connected_addr, &sockaddr_size);
            if(connected_handle == -1)
            {
                if(!graceful_exit)
                {
                    // failure occured when accepting, return
                    //fprintf(stdout, "FAILED TO ACCEPT!\n");
                    cleanup(fp, socket_handle, connected_handle, -1);
                }
            }
            else
            {
                // log message to syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client
                struct sockaddr_in *address = (struct sockaddr_in *)&connected_addr;
                inet_ntop(AF_INET, &(address)->sin_addr, client_address, INET_ADDRSTRLEN);
                syslog(LOG_INFO, "Accepted connection from %s", client_address);

                // create thread
                struct socket_thread_args * thread_args;
                thread_args = malloc(sizeof(struct socket_thread_args));
                memset(thread_args, 0, sizeof(thread_args));
                thread_args->done_flag = false;
                thread_args->connected_handle = connected_handle;
                thread_args->file_pointer = fp;
                thread_args->socket_handle = socket_handle;
                thread_args->file_mutex = &file_mutex;
                //fprintf(stdout, "Main: Creating socket thread, connected handle: %d!\n", connected_handle);
                int create_result = pthread_create(&thread_args->thread_id, NULL, socket_thread, thread_args);

                if(create_result == 0)
                {
                    //fprintf(stdout, "Main: Thread created: %lu, adding to list!\n", thread_args->thread_id);
                    // add thread to list
                    SLIST_INSERT_HEAD(&head, thread_args, thread_entries);
                }
                else
                {
                    //fprintf(stdout, "Main: Failure to create thread!\n");
                }
            }

            // check threads, join if done
            SLIST_FOREACH(temp_entry, &head, thread_entries)
                if(temp_entry->done_flag == true && temp_entry->thread_id != 0)
                {
                    //fprintf(stdout, "Main: Thread completed: %lu, joining!\n", temp_entry->thread_id);
                    pthread_join(temp_entry->thread_id, NULL);
                    temp_entry->thread_id = 0;
                    shutdown(temp_entry->connected_handle, SHUT_RDWR);
                    close(temp_entry->connected_handle);
                }

        }
    }

    // log closed connection message
    syslog(LOG_INFO, "Closed connection from %s", client_address);

    // wait for all threads to complete
    //fprintf(stdout, "Closing server, waiting for threads to complete!\n");
    bool waiting = true;
    while(waiting)
    {
        waiting = false;
        // check threads, join if done; otherwise, keep waiting
        SLIST_FOREACH(temp_entry, &head, thread_entries)
            if(temp_entry->done_flag == true)
            {
                if(temp_entry->thread_id != 0)
                {
                    //fprintf(stdout, "Main: Thread completed during close: %lu, joining!\n", temp_entry->thread_id);
                    pthread_join(temp_entry->thread_id, NULL);
                    temp_entry->thread_id = 0;
                    shutdown(temp_entry->connected_handle, SHUT_RDWR);
                    close(temp_entry->connected_handle);
                }
            }
            else
            {
                waiting = true;
            }
    }

    // clean up memory
    while(!SLIST_EMPTY(&head))
    {
        temp_entry = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, thread_entries);
        free(temp_entry);
    }

    //fprintf(stdout, "All threads complete, cleaning up!\n");
    cleanup(fp, socket_handle, connected_handle, 0);
}

static void signal_handler(int signal_number)
{
    int errno_saved = errno;
    switch(signal_number)
    {
        case SIGINT:
        case SIGTERM:
            // set exit flag
            graceful_exit = true;

            // log that signal was caught
            syslog(LOG_INFO, "Caught signal, exiting");
            break;

        default:
            break;
    }
    errno = errno_saved;
}

static void cleanup(FILE * file_pointer, int socket_handle, int connected_handle, int exit_status)
{
    if(socket_handle > 0)
    {
        shutdown(socket_handle, SHUT_RDWR);
        close(socket_handle);
    }

    if(connected_handle > 0)
    {
        close(connected_handle);
    }
    
    if(file_pointer != NULL)
    {
        fclose(file_pointer);
    }

    if(USE_AESD_CHAR_DEVICE != 1)
    {
        remove(CONN_FILE);
    }
    
    exit(exit_status);
}

static void * socket_thread(void * args)
{
    ssize_t bytes_received;
    size_t buffer_bytes_used;
    size_t buffer_bytes_remaining;
    char buffer[BUFFER_SIZE];
    struct socket_thread_args *thread_args;
    int store_return;
    int fd_driver;
    struct aesd_seekto seekto;
    char * keyword;
    char * write_cmd;
    char * write_cmd_offset;
    unsigned long write_cmd_unsigned;
    unsigned long write_cmd_offset_unsigned;
    thread_args = (struct socket_thread_args *)args;
    FILE * fp_char = NULL;

    // receive data from connection and append to file
    buffer_bytes_used = 0;
    memset(&buffer, 0, sizeof(buffer));

    if(USE_AESD_CHAR_DEVICE)
    {
        fp_char= fopen(AESD_DEVICE, "a+");
        if(fp_char == NULL)
        {
            // failure to open driver
            syslog(LOG_ERR, "Failed to open the driver during write!");
        }
    }

    // In the future, this could be adjusted for receiving larger amounts than the buffer..but I had some annoying blocking here
    bytes_received = 0;
    buffer_bytes_remaining = sizeof( buffer ) - buffer_bytes_used;

    // receive up to what is remaining in the buffer
    bytes_received = recv(thread_args->connected_handle, &buffer[buffer_bytes_used], buffer_bytes_remaining, 0);
    if(bytes_received > 0)
    {
        buffer_bytes_used += bytes_received;
    }
    else if(bytes_received < 0)
    {
        syslog(LOG_ERR, "Error occurred when receiving from socket");
        thread_args->done_flag = true;
        fclose(fp_char);
        return 0;
    }
    
    pthread_mutex_lock(thread_args->file_mutex);

    // intercept ioctl command and don't send if that's what was received
    fd_driver = fileno(fp_char);

    // if string contains the command, parse it and use ioctl
    if(strstr(buffer, IOC_CMD) != NULL)
    {
        // split out the commands
        keyword = strtok(buffer, ":");
        write_cmd = strtok(NULL, ",");
        write_cmd_offset = strtok(NULL, ",");
        syslog(LOG_NOTICE, "ioctl cmd received: %s, %s", write_cmd, write_cmd_offset);

        // convert to numbers
        seekto.write_cmd = strtoul(write_cmd, NULL, 10);
        seekto.write_cmd_offset = strtoul(write_cmd_offset, NULL, 10);
        syslog(LOG_NOTICE, "ioctl cmd values: %d, %d", seekto.write_cmd, seekto.write_cmd_offset);
        
        // send the command
        int result_ret = ioctl(fd_driver, AESDCHAR_IOCSEEKTO, &seekto);
    }
    // otherwise, just write what was sent, then seek to the start for the read that follows
    else
    {
        store_return = fwrite(buffer, sizeof(char), buffer_bytes_used, fp_char);
        fseek(fp_char, 0, SEEK_SET);
    }

    pthread_mutex_unlock(thread_args->file_mutex);

    if(store_return == EOF)
    {
        syslog(LOG_ERR, "Failed to append to file!");
        thread_args->done_flag = true;
        return 0;
    }
    
    pthread_mutex_lock(thread_args->file_mutex);

    memset(&buffer, 0, sizeof(buffer));

    ssize_t bytes_sent = 0;
    size_t bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, fp_char);
    syslog(LOG_NOTICE, "Done reading characters, found: %li", bytes_read);

    while(bytes_read > 0)
    {
        size_t read_until = bytes_read;

        // iterate through the buffer, until finished sending
        ssize_t send_return = 0;
        while(bytes_sent < read_until)
        {
            send_return = send(thread_args->connected_handle, &buffer[bytes_sent], read_until, 0);
            
            if(send_return > 0)
            {
                syslog(LOG_NOTICE, "Sent characters: %li", send_return);
                bytes_sent += send_return;
            }
            else
            {
                syslog(LOG_NOTICE, "Send fail");
                thread_args->done_flag = true;
                return 0;
            }
        }
        bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, fp_char);
        syslog(LOG_NOTICE, "read more characters, found: %li", bytes_read);
        bytes_sent = 0;
    }
    fclose(fp_char);
    pthread_mutex_unlock(thread_args->file_mutex);

    syslog(LOG_NOTICE, "Done sending, mutex unlocked");
    thread_args->done_flag = true;
    
    return 0;
}

static void timer_signal()
{
    clock_t current_time;
    time_t time_to_output;
    struct tm *tmp;
    char output_string[200];
    size_t string_length;
    memset(output_string, 0, sizeof(output_string));

    //fprintf(stdout, "Timer Thread: starting timer!\n");

    current_time = clock();
    //fprintf(stdout, "Timer Thread: outputting time!\n");
    time_to_output = time(NULL);
    tmp = localtime(&time_to_output);

    string_length = strftime(output_string, sizeof(output_string), "timestamp:%F %H %M %S\n", tmp);
    if(string_length != 0)
    {
        //fprintf(stdout, "Timer Thread: attempting to grab mutex!\n");
        pthread_mutex_lock(&file_mutex);
        //fprintf(stdout, "Timer Thread: grabbed mutex, writing to file!\n");
        int file_write_return;
        file_write_return = fwrite(output_string, sizeof(char), string_length, fp);
        if(file_write_return == EOF)
        {
            syslog(LOG_ERR, "Failed to write timestamp!");
        }
        //fprintf(stdout, "Timer Thread: unlocking mutex!\n");
        pthread_mutex_unlock(&file_mutex);
    }
}