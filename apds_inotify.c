/*
 * Inotify thread, multiplexes inotify events between threads
 */

#include <errno.h>
#include <glib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apdate_common.h"
#include "apds_inotify.h"
#include "apds_main.h"
#include "apds_proto.h"

static pthread_mutex_t pipelist_mut = PTHREAD_MUTEX_INITIALIZER;
static int wd_list_count = WDLIST_INIT, inotify_fd;
static struct wd_subs *wd_list;

static int wd_alloc(const char *path)
{
	int i;
	struct stat st;

	for (i=0; i<wd_list_count; i++)
		if (wd_list[i].wd == 0)
			break;
	if (i == wd_list_count) {
		wd_list = realloc(wd_list, C_WDLIST_SIZE * 2);
		if (wd_list == NULL) {
			syslog(LOG_ERR, "Failed to realloc wd_list from %lu to %lu",
			       C_WDLIST_SIZE, C_WDLIST_SIZE * 2);
			exit(80);
		}
		memset(&wd_list[wd_list_count], 0, C_WDLIST_SIZE);
		wd_list_count *= 2;
	}
	wd_list[i].name = strdup(path);
	if (wd_list[i].name == NULL)
		goto errout;
	if (stat(wd_list[i].name, &st) != 0)
		goto errout;

	wd_list[i].wd = inotify_add_watch(inotify_fd, wd_list[i].name, IN_CREATE);
	if (wd_list[i].wd < 0)
		goto errout;
	wd_list[i].subscribers_count = WDLIST_INIT;
	wd_list[i].subscribers_write_fds = malloc(C_SUBLIST_SIZE(i));
	wd_list[i].subscribers_read_fds = malloc(C_SUBLIST_SIZE(i));
	if (wd_list[i].subscribers_write_fds == NULL ||
	    wd_list[i].subscribers_read_fds == NULL)
		goto errout;
       
	memset(wd_list[i].subscribers_write_fds, 0, C_SUBLIST_SIZE(i));
	memset(wd_list[i].subscribers_read_fds, 0, C_SUBLIST_SIZE(i));

	return i;

errout:
	free(wd_list[i].name);
	free(wd_list[i].subscribers_write_fds);
	free(wd_list[i].subscribers_read_fds);
	if (wd_list[i].wd > 0) {
		inotify_rm_watch(inotify_fd, wd_list[i].wd);
		wd_list[i].wd = 0;
	}
	return -1;
}

static int wd_new_sub(const int wd_index, const int write_fd, const int read_fd)
{
	int i;
	int *wfds, *rfds;

	wfds = wd_list[wd_index].subscribers_write_fds;
	rfds = wd_list[wd_index].subscribers_read_fds;

	for (i=0; i<wd_list[wd_index].subscribers_count; i++) {
		if ((wfds[i] == 0) && (rfds[i] == 0))
			break;
		// Already subscribed
		if ((wfds[i] == write_fd) && (rfds[i] == read_fd))
			return 0;
	}
	if (i == wd_list[wd_index].subscribers_count) {
		wfds = realloc(wfds, C_SUBLIST_SIZE(wd_index) * 2);
		rfds = realloc(rfds, C_SUBLIST_SIZE(wd_index) * 2);
		if (wfds == NULL || rfds == NULL) {
			syslog(LOG_ERR, "Failed to realloc wfds or rfds");
			exit(81);
		}
		wd_list[wd_index].subscribers_write_fds = wfds;
		wd_list[wd_index].subscribers_read_fds = rfds;
		memset(&(wfds[i]), 0, C_SUBLIST_SIZE(wd_index));
		memset(&(rfds[i]), 0, C_SUBLIST_SIZE(wd_index));
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
	char *q;
	struct apds_session *apdss;

	apdss = (struct apds_session *) pthread_getspecific(apds_key);
	/* We're getting full file path here, so strip filename */
	q = g_path_get_dirname(path);
	if (q == NULL)
		return -1;

	pthread_mutex_lock(&pipelist_mut);
	for (i=0; i<wd_list_count; i++)
		if (wd_list[i].wd != 0 && strcmp(q, wd_list[i].name) == 0)
			break;
	if (i == wd_list_count)
		i = wd_alloc(q);
	free(q);
	if (i < 0) {
		pthread_mutex_unlock(&pipelist_mut);
		syslog(LOG_ERR, "%lli: Failed to reallocate watch list", (long long int) pthread_self());
		return i;
	}
	if (apdss->i_wfd < 0 || apdss->i_rfd < 0) {
		if (pipe(filedes) < 0) {
			pthread_mutex_unlock(&pipelist_mut);
			syslog(LOG_ERR, "%lli: Failed to created pipe for inotify", (long long int) pthread_self());
			return 1;
		}
		apdss->i_wfd = filedes[1];
		apdss->i_rfd = filedes[0];
	}
	wd_new_sub(i, apdss->i_wfd, apdss->i_rfd);
	pthread_mutex_unlock(&pipelist_mut);
	DEBUG(syslog(LOG_DEBUG, "%lli: Subscribed inotify to %s", (long long int) pthread_self(), path));
	return 0;
}

static void wd_list_free(int i)
{
	if (wd_list[i].wd > 0) {
		free(wd_list[i].subscribers_read_fds);
		free(wd_list[i].subscribers_write_fds);
		free(wd_list[i].name);
		inotify_rm_watch(inotify_fd, wd_list[i].wd);
		wd_list[i].wd = 0;
	}
}

int inotify_unsub(int req_i)
{
	int i, j;
	char *path, *q;
	struct apds_session *apdss;

	apdss = (struct apds_session *) pthread_getspecific(apds_key);

	path = g_array_index(apdss->reqs, char *, req_i);
	/* We're getting full file path here, so strip filename */
	q = g_path_get_dirname(path);

	pthread_mutex_lock(&pipelist_mut);
	for (i=0; i < wd_list_count; i++)
		if (wd_list[i].wd != 0 && strcmp(q, wd_list[i].name) == 0)
			break;
	free(q);
	if (i == wd_list_count) {
		pthread_mutex_unlock(&pipelist_mut);
		return -1;
	}
	for (j = 0; j < wd_list[i].subscribers_count; j++)
		if (wd_list[i].subscribers_read_fds[j] == apdss->i_rfd)
			break;
	if (j == wd_list[i].subscribers_count) {
		pthread_mutex_unlock(&pipelist_mut);
		return -1;
	}
	/* Unsubscribe from particular update channel */
	wd_list[i].subscribers_read_fds[j] = 0;
	wd_list[i].subscribers_write_fds[j] = 0;

	// Do we need this watch descriptor still?
	for (j=0; j<wd_list[i].subscribers_count; j++)
		if (wd_list[i].subscribers_read_fds[j] != 0)
			break;
	if (j == wd_list[i].subscribers_count) {
		wd_list_free(i);
	}

	/* Do we need this pipe still? */
	for (i=0; i < wd_list_count; i++)
		if (wd_list[i].wd != 0) {
			for (j = 0; j < wd_list[i].subscribers_count; j++)
				if (wd_list[i].subscribers_read_fds[j] ==
				    apdss->i_rfd)
					break;
			if (j < wd_list[i].subscribers_count)
				break;
		}
	if (i == wd_list_count) {
		close(apdss->i_rfd);
		close(apdss->i_wfd);
		apdss->i_rfd = -1;
		apdss->i_wfd = -1;
	}

	pthread_mutex_unlock(&pipelist_mut);
	free(path);
	g_array_remove_index(apdss->reqs, req_i);
	return 0;
}

static int inotify_push_upd(int wd, char *fname)
{
	int i, j;
	char *p;

	for (i = 0; i < wd_list_count; i++)
		if (wd_list[i].wd == wd)
			break;

	if (i == wd_list_count) {
		syslog(LOG_ERR, "No handler for inotify watch!");
		return -1;
	}

	p = g_build_filename(wd_list[i].name, fname, (char*) NULL);
	for (j = 0; j < wd_list[i].subscribers_count; j++)
		if (wd_list[i].subscribers_write_fds[j] > 0) {
			DEBUG(syslog(LOG_DEBUG, "notifying about %s, %d", p, j));
			write(wd_list[i].subscribers_write_fds[j], p,
			      strlen(p) + 1);
		}
	free(p);
	return 0;
}

void *apds_inotify_thread(void *smth)
{
	// Not interested in any kind of joining here
	pthread_detach(pthread_self());
	pthread_mutex_lock(&pipelist_mut);

	wd_list_count = WDLIST_INIT;
	wd_list = malloc(C_WDLIST_SIZE);
	memset(wd_list, 0, C_WDLIST_SIZE);

	inotify_fd = inotify_init();
	pthread_mutex_unlock(&pipelist_mut);

	if (inotify_fd < 0) {
		syslog(LOG_ERR, "Can't initialize inotify");
		exit(10);
	}
	pthread_barrier_wait(&initbarrier);
	while (1) {
		char buf[IEVENT_BUF];
		int len, i = 0;

		len = read(inotify_fd, buf, IEVENT_BUF);

		/*
		 * Ignore EINTR for debugging, see
		 * http://lkml.org/lkml/2006/7/3/133
		 */
		if (len < 0 && errno != EINTR) {
			perror("Inotify failure\n");
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
