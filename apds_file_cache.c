#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "apds_file_cache.h"
#include "apds_main.h"

static struct mapd_upd_file *upd_list;
static unsigned int upd_list_size = MAPD_LIST_INIT_SIZE;
static pthread_rwlock_t updlist_lock = PTHREAD_RWLOCK_INITIALIZER;

static int map_upd_file_to_list(const char *fname, const unsigned int i)
{
	upd_list[i].fd = open(fname, O_RDONLY);
	if (upd_list[i].fd < 0) {
		syslog(LOG_ERR, "Failed to open %s: %s", fname, strerror(errno));
		return -1;
	}
	/* Get file size*/
	if ((upd_list[i].map.size = lseek(upd_list[i].fd, 0, SEEK_END)) < 0
	    || lseek(upd_list[i].fd, 0, SEEK_SET) != 0) {
		close(upd_list[i].fd);
		return -1;
	}

	upd_list[i].map.mmap = mmap(NULL, upd_list[i].map.size, PROT_READ,
				    MAP_SHARED | MAP_POPULATE, upd_list[i].fd,
				    0);
	if (upd_list[i].map.mmap == MAP_FAILED) {
		upd_list[i].map.mmap = NULL;
		close(upd_list[i].fd);
		return -1;
	}
	upd_list[i].name = strdup(fname);
	if (upd_list[i].name == NULL) {
		munmap(upd_list[i].map.mmap, upd_list[i].map.size);
		upd_list[i].map.mmap = NULL;
		close(upd_list[i].fd);
		return -1;
	}
	pthread_rwlock_init(&upd_list[i].lock, NULL);
	pthread_rwlock_rdlock(&upd_list[i].lock);
	return 0;
}

static struct upd_map map_upd_file(const char *fname)
{
	unsigned int i;
	int ret;

	pthread_rwlock_wrlock(&updlist_lock);
	for (i = 0; i < upd_list_size; i++)
		if (upd_list[i].name == NULL)
			break;
	if (i == upd_list_size) {
		upd_list = realloc(upd_list, UPD_LIST_SIZE * 2);
		if (upd_list == NULL) {
			syslog(LOG_ERR, "Growing upd_list failed!");
			exit(300);
		}
		memset(&(upd_list[i]), 0, UPD_LIST_SIZE);
		upd_list_size *= 2;
	}
	ret = map_upd_file_to_list(fname, i);
	pthread_rwlock_unlock(&updlist_lock);
	if (ret == 0)
		return upd_list[i].map;
	else
		return (struct upd_map) {0, NULL};
}

struct upd_map get_upd_map(const char *fname)
{
	unsigned int i;

	pthread_rwlock_rdlock(&updlist_lock);
	for (i = 0; i < upd_list_size; i++)
		if (upd_list[i].name != NULL &&
		    (strcmp(upd_list[i].name, fname) == 0)) {
			pthread_rwlock_rdlock(&upd_list[i].lock);
			pthread_rwlock_unlock(&updlist_lock);
			return upd_list[i].map;
		}
	pthread_rwlock_unlock(&updlist_lock);
	return map_upd_file(fname);
}

void release_upd_file(struct upd_map upf)
{
	unsigned int i;

	pthread_rwlock_rdlock(&updlist_lock);
	for (i = 0; i < upd_list_size; i++)
		if (upd_list[i].map.mmap == upf.mmap) {
			pthread_rwlock_unlock(&upd_list[i].lock);
			break;
		}
	pthread_rwlock_unlock(&updlist_lock);
}

static void release_mapd_file(unsigned int i)
{
	free(upd_list[i].name);
	upd_list[i].name = NULL;
	munmap(upd_list[i].map.mmap, upd_list[i].map.size);
	upd_list[i].map.mmap = NULL;
	close(upd_list[i].fd);
}

void *apds_fcache_thread(void *smth)
{
	unsigned int i;

	// Not interested in any kind of joining here
	pthread_detach(pthread_self());
	i = UPD_LIST_SIZE;
	pthread_rwlock_wrlock(&updlist_lock);
	upd_list = malloc(i);
	if (upd_list == NULL) {
		syslog(LOG_ERR, "Unable to initialize file cache");
		exit(200);
	}
	memset(upd_list, 0, i);
	pthread_rwlock_unlock(&updlist_lock);
	pthread_barrier_wait(&initbarrier);

	/* Sort of garbage collection */
	while (1) {
		sleep(120);
		pthread_rwlock_wrlock(&updlist_lock);
		for (i = 0; i < upd_list_size; i++)
			if (upd_list[i].name != NULL &&
			    (pthread_rwlock_trywrlock(&upd_list[i].lock) == 0)) {
				release_mapd_file(i);
				pthread_rwlock_unlock(&upd_list[i].lock);
				pthread_rwlock_destroy(&upd_list[i].lock);
			}
		pthread_rwlock_unlock(&updlist_lock);
	}
}
