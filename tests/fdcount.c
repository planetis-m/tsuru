#include <dirent.h>
#include <errno.h>

int tsuru_test_fd_count(void) {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) return -1;
  int count = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(dir))) {
    if (entry->d_name[0] == '.' &&
        (entry->d_name[1] == '\0' ||
         (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) continue;
    ++count;
  }
  int failed = errno != 0;
  if (closedir(dir) != 0) failed = 1;
  return failed ? -1 : count;
}
