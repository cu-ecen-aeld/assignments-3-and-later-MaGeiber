#include <stdio.h>
#include <syslog.h>

int main(int argc, char *argv[])
{
    FILE * fp;

    // open the log
    openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);

    // exit with value 1 if arguments not specified correctly
    // first argument is full path to file
    // second arg is text to write to file
    if(argc != 3)
    {
        syslog(LOG_ERR, "Incorrect number of arguments passed in!");
        return 1;
    }

    // log information about what the program is doing
    syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);

    // open the file for writing
    fp = fopen(argv[1], "w");

    // could not open the file, indicate error
    if(fp == NULL)
    {
        syslog(LOG_ERR, "Failed to open the file specified!");
        return 1;
    }

    // write the argument to the file
    fprintf(fp, "%s", argv[2]);

    // done with the file, close
    fclose(fp);
    
    return 0;
}