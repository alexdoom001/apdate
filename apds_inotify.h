#ifndef APDS_INOTIFY_H
#define APDS_INOTIFY_H 1

struct wd_subs {
	int wd;
	char *name;
	int subscribers_count;
	int *subscribers_write_fds;
	int *subscribers_read_fds;
};

#define IEVENT_SIZE sizeof(struct inotify_event)
#define IEVENT_BUF 16*(sizeof(struct inotify_event) + 16)

#define C_WDLIST_SIZE (sizeof(struct wd_subs) * wd_list_count)
#define WDLIST_INIT 8
#define C_SUBLIST_SIZE(i) (sizeof(int) * wd_list[i].subscribers_count)

int inotify_sub(const char *path);
int inotify_unsub(const int rd_pipe);
void *apds_inotify_thread(void *smth);

#endif
