#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define SOCK_PORT "9000"
#define CONN_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024

static bool graceful_exit = false;

static void signal_handler(int signal_number);
static void cleanup(FILE * file_pointer, int socket_handle, int connected_handle, int exit_status);

int main(int argc, char *argv[])
{
    FILE * fp = NULL;
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
            fprintf(stdout, "FAILED TO GET SOCKET HANDLE!\n");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        // allow address reuse
        setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &set_socket_option, sizeof(set_socket_option));

        // bind
        bind_return = bind(socket_handle, returned_addr_info->ai_addr, returned_addr_info->ai_addrlen);
        if(bind_return != 0)
        {
            // failed to bind, return
            fprintf(stdout, "FAILED TO BIND! %d error: %d\n", bind_return, errno);
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        if(argc == 2)
        {
            if(strcmp(argv[1], "-d") == 0)
            {
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
            }
        }

        // free the malloc'd memory
        freeaddrinfo(returned_addr_info);

        // listen
        listen_return = listen(socket_handle, SOMAXCONN);
        if(listen_return != 0)
        {
            // failure from listen, return
            fprintf(stdout, "FAILED TO LISTEN!\n");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        // accept connection
        connected_handle = accept(socket_handle, &connected_addr, &sockaddr_size);
        if(connected_handle == -1)
        {
            if(graceful_exit)
            {
                cleanup(fp, socket_handle, connected_handle, 0);
            }
            // failure occured when accepting, return
            fprintf(stdout, "FAILED TO ACCEPT!\n");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        // log message to syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client
        struct sockaddr_in *address = (struct sockaddr_in *)&connected_addr;
        inet_ntop(AF_INET, &(address)->sin_addr, client_address, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", client_address);

        // open the file to append to
        fp = fopen(CONN_FILE, "a+");
        if(fp == NULL)
        {
            // failure to open file for appending
            syslog(LOG_ERR, "Failed to open the file for appending!");
            cleanup(fp, socket_handle, connected_handle, -1);
        }

        // receive data from connection and append to file
        buffer_bytes_used = 0;
        memset(&buffer, 0, sizeof(buffer));
        bool found_newline = false;
        do
        {
            bytes_received = 0;
            buffer_bytes_remaining = sizeof( buffer ) - buffer_bytes_used;
        
            // receive up to what is remaining in the buffer
            bytes_received = recv(connected_handle, &buffer[buffer_bytes_used], buffer_bytes_remaining, 0);
            if(bytes_received > 0)
            {
                fprintf(stdout, "Received %ld bytes\n", bytes_received);
                buffer_bytes_used += bytes_received;
            }
            else if(bytes_received < 0)
            {
                fprintf(stdout, "Received error: %ld, errno: %d\n", bytes_received, errno);
            }
            else
            {
                continue;
            }

            // check the buffer for newline, append when newline hit
            // check if buffer is full, flush to file, start over
            found_newline = (strchr(buffer, '\n') != NULL) ? true : false;
            if(found_newline || buffer_bytes_used >= BUFFER_SIZE)
            {
                fprintf(stdout, "Found newline: %d\n", found_newline);
                int store_return;
                store_return = fwrite(buffer, sizeof(char), buffer_bytes_used, fp);
                if(store_return == EOF)
                {
                    syslog(LOG_ERR, "Failed to append to file!");
                    cleanup(fp, socket_handle, connected_handle, -1);
                }
                fprintf(stdout, "Stored message\n");
                buffer_bytes_used = 0;
                memset(&buffer, 0, sizeof(buffer));
            }
        } while (bytes_received > 0 && !found_newline);
        fprintf(stdout, "Done receiving\n");
        
        // send content of file back to sender
        int seek_return = fseek(fp, 0, SEEK_SET);
        if(seek_return < 0)
        {
            fprintf(stdout, "Failed to seek while reading\n");
        }
        ssize_t bytes_sent = 0;
        memset(&buffer, 0, sizeof(buffer));
        size_t bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, fp);
        while(bytes_read > 0)
        {
            size_t read_until = bytes_read;
            char *found_char = strchr(buffer, '\n');

            // iterate through the buffer, until finished sending
            ssize_t send_return = 0;
            while(bytes_sent < read_until)
            {
                fprintf(stdout, "Sending bytes until: %lu\n", read_until);
                send_return = send(connected_handle, &buffer[bytes_sent], read_until, 0);
                
                if(send_return > 0)
                {
                    bytes_sent += send_return;
                }
                else
                {
                    fprintf(stdout, "Send return val: %ld\n", send_return);
                }
            }
            bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, fp);
            bytes_sent = 0;
        }
        fprintf(stdout, "Done sending\n");

        // log closed connection message
        syslog(LOG_INFO, "Closed connection from %s", client_address);

        close(socket_handle);
        close(connected_handle);
    }

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

    remove(CONN_FILE);
    exit(exit_status);
}