#pragma once

pid_t fork();
pid_t waitpid(pid_t pid, int *status, int options);
void _exit(int status);
int execvp(const char *file, char *const argv[]);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int unlink();
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
