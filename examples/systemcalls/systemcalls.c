#include "systemcalls.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    int return_sys;

    // If the command going into system() is NULL, it checks if the shell is available
    if(cmd == NULL)
    {
        if(system(cmd) != 0)
        {
            // shell is available
        }
        else
        {
            // shell is unavailable
        }
    }
    else
    {
        return_sys = system(cmd);
        // check for error codes: -1 issues with child process, 127 if shell could not execute
        if(return_sys == -1 || return_sys == 127)
        {
            return false;
        }
    }

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    pid_t pid;
    int child_exit_status;
    int child_return_val;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

    // initial checks
    if(command == NULL)
    {
        return false;
    }

    // fork a process
    pid = fork();

    // failure to fork, return
    if( pid == -1)
    {
        return false;
    }
    // we are the child process, do the command
    else if(pid == 0)
    {
        child_return_val = execv(command[0], command);
        exit(child_return_val);
    }
    // we are the parent process, wait then return child status
    else
    {
        wait(&child_exit_status);
        if(WIFEXITED(child_exit_status))
        {
            return WEXITSTATUS(child_exit_status) == 0;
        }
    }

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    pid_t pid;
    int fd;
    int child_exit_status;
    int child_return_val;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

    // initial checks
    if(command == NULL)
    {
        return false;
    }

    // attempt to open the file specified
    fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);

    // file open failed
    if( fd < 0)
    {
        return false;
    }

    // fork a process
    pid = fork();

    // failure to fork, return
    if( pid == -1)
    {
        return false;
    }
    // we are the child process, do the command
    else if(pid == 0)
    {
        // try to redirect standard out to the file
        if(dup2(fd, STDOUT_FILENO) < 0)
        {
            // failed
            return false;
        }

        // close the file
        close(fd);

        // execute the command
        child_return_val = execv(command[0], command);
        exit(child_return_val);
    }
    // we are the parent process, wait then return child status
    else
    {
        close(fd);
        wait(&child_exit_status);

        if(WIFEXITED(child_exit_status))
        {
            return WEXITSTATUS(child_exit_status) == 0;
        }
    }

    va_end(args);

    return true;
}
