/*
 * Inotify thread, multiplexes inotify events between threads
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "apds_inotify.h"

static pthread_mutex_t pipelist_mut = PTHREAD_MUTEX_INITIALIZER;
static int wd_list_count, inotify_fd;
static struct wd_subs *wd_list;

static int wd_alloc(const char *path)
{
	int i;

	for (i=0; i<wd_list_count; i++)
		if (wd_list[i].wd == -1)
			break;
	if (i == wd_list_count) {
		wd_list = realloc(wd_list, C_WDLIST_SIZE * 2);
		if (wd_list == NULL) {
			printf("Failed to realloc wd_list from %lu to %lu\n",
			       C_WDLIST_SIZE, C_WDLIST_SIZE * 2);
			exit(80);
		}
		memset(wd_list + C_WDLIST_SIZE, -1, C_WDLIST_SIZE);
		wd_list_count *= 2;
	}
	wd_list[i].wd = inotify_add_watch(inotify_fd, path, IN_CREATE);
	wd_list[i].name = strdup(path);
	wd_list[i].subscribers_count = WDLIST_INIT;
	wd_list[i].subscribers_write_fds = malloc(C_SUBLIST_SIZE(i));
	memset(wd_list[i].subscribers_write_fds, -1, C_SUBLIST_SIZE(i));
	wd_list[i].subscribers_read_fds = malloc(C_SUBLIST_SIZE(i));
	memset(wd_list[i].subscribers_read_fds, -1, C_SUBLIST_SIZE(i));

	return i;
}

static int wd_new_sub(const int wd_index, const int write_fd, const int read_fd)
{
	int i;
	int *wfds, *rfds;

	wfds = wd_list[wd_index].subscribers_write_fds;
	rfds = wd_list[wd_index].subscribers_read_fds;

	for (i=0; i<wd_list[wd_index].subscribers_count; i++)
		if ((wfds[i] == -1) && (rfds[i] == -1))
			break;
	if (i == wd_list[wd_index].subscribers_count) {
		wfds = realloc(wfds, C_SUBLIST_SIZE(wd_index) * 2);
		rfds = realloc(rfds, C_SUBLIST_SIZE(wd_index) * 2);
		if (wfds == NULL || rfds == NULL) {
			printf("Failed to realloc wfds or rfds\n");
			exit(81);
		}
		wd_list[wd_index].subscribers_write_fds = wfds;
		wd_list[wd_index].subscribers_read_fds = rfds;
		memset(&(wfds[i]), -1, C_SUBLIST_SIZE(wd_index));
		memset(&(rfds[i]), -1, C_SUBLIST_SIZE(wd_index));
		wd_list[wd_index].subscribers_count *= 2;
	}
	wfds[i] = write_fd;
	rfds[i] = read_fd;
	return 0;
}

int inotify_sub(const char *path)
{
	int i;
	int filedes[2];

	pthread_mutex_lock(&pipelist_mut);
	for (i=0; i<wd_list_count; i++)
		if (wd_list[i].wd != -1 && strcmp(path, wd_list[i].name) == 0)
			break;
	if (i == wd_list_count)
		i = wd_alloc(path);
	pipe(filedes);
	wd_new_sub(i, filedes[1], filedes[0]);

	pthread_mutex_unlock(&pipelist_mut);
	return filedes[0];
}

static void wd_list_free(int i)
{
	if (wd_list[i].wd > 0) {
		free(wd_list[i].subscribers_read_fds);
		free(wd_list[i].subscribers_write_fds);
		free(wd_list[i].name);
		inotify_rm_watch(inotify_fd, wd_list[i].wd);
		wd_list[i].wd = -1;
	}
}

int inotify_unsub(const int rd_pipe)
{
	int i, j;

	pthread_mutex_lock(&pipelist_mut);

	for (i=0; i<wd_list_count; i++)
		if (wd_list[i].wd != -1) {
			for (j=0; j<wd_list[i].subscribers_count; j++)
				if (wd_list[i].subscribers_read_fds[j] ==
				    rd_pipe)
					break;
			if (j < wd_list[i].subscribers_count)
				break;
		}
	if (i == wd_list_count)
		return -1;
	close(wd_list[i].subscribers_read_fds[j]);
	close(wd_list[i].subscribers_write_fds[j]);
	wd_list[i].subscribers_read_fds[j] = -1;
	wd_list[i].subscribers_write_fds[j] = -1;

	// Do we need this watch descriptor still?
	for (j=0; j<wd_list[i].subscribers_count; j++)
		if (wd_list[i].subscribers_read_fds[j] != -1)
			break;
	if (j == wd_list[i].subscribers_count) {
		wd_list_free(i);
	}
	pthread_mutex_unlock(&pipelist_mut);
	return 0;
}

static int inotify_push_upd(int wd, char *fname)
{
	int i, j;

	for (i = 0; i < wd_list_count; i++)
		if (wd_list[i].wd == wd)
			break;

	if (i == wd_list_count) {
		fprintf(stderr, "No handler for inotify watch!\n");
		return -1;
	}

	for (j = 0; j < wd_list[i].subscribers_count; j++)
		if (wd_list[i].subscribers_write_fds[j] > 0)
			write(wd_list[i].subscribers_write_fds[j], fname,
			      strlen(fname) + 1);
	return 0;
}

void *apds_inotify_thread(void *smth)
{
	pthread_mutex_lock(&pipelist_mut);

	wd_list_count = WDLIST_INIT;
	wd_list = malloc(C_WDLIST_SIZE);
	memset(wd_list, -1, C_WDLIST_SIZE);

	inotify_fd = inotify_init();

	if (inotify_fd < 0) {
		fprintf(stderr, "Can't initialize inotify\n");
		exit(10);
	}
	pthread_mutex_unlock(&pipelist_mut);
	while (1) {
		char buf[IEVENT_BUF];
		int len, i = 0;

		len = read(inotify_fd, buf, IEVENT_BUF);
		if (len < 0) {
			fprintf(stderr, "Inotify failure\n");
			exit(11);
		}
		while (i < len) {
			struct inotify_event *event = (struct inotify_event *)
				&buf[i];
			if (event->len)
				if (!(event->mask & (IN_ISDIR | IN_IGNORED)))
					inotify_push_upd(event->wd, event->name);
			i += IEVENT_SIZE + event->len;
		}
	}
}
