#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "apds_file_cache.h"
#include "apds_main.h"

static struct mapd_upd_file *upd_list;
static unsigned int upd_list_size = MAPD_LIST_INIT_SIZE;
static pthread_rwlock_t updlist_lock = PTHREAD_RWLOCK_INITIALIZER;

static int map_upd_file_to_list(const char *fname, const unsigned int i)
{
	char *path;
	struct stat fst;

	path = strconcat(upddb, fname);
	if (stat(path, &fst) != 0) {
		free(path);
		return -1;
	}
	upd_list[i].map.size = fst.st_size;
	upd_list[i].fd = open(path, O_RDONLY);
	if (upd_list[i].fd < 0) {
		free(path);
		return -1;
	}
	upd_list[i].map.mmap = mmap(NULL, upd_list[i].map.size, PROT_READ,
				    MAP_SHARED | MAP_POPULATE, upd_list[i].fd,
				    0);
	if (upd_list[i].map.mmap == MAP_FAILED) {
		upd_list[i].map.mmap = NULL;
		close(upd_list[i].fd);
		free(path);
		return -1;
	}
	upd_list[i].name = strdup(fname);
	if (upd_list[i].name == NULL) {
		munmap(upd_list[i].map.mmap, upd_list[i].map.size);
		upd_list[i].map.mmap = NULL;
		close(upd_list[i].fd);
		free(path);
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
		if (upd_list[i].name == NULL && upd_list[i].map.mmap == NULL)
			break;
	if (i == upd_list_size) {
		upd_list = realloc(upd_list, upd_list_size *
				   sizeof(struct mapd_upd_file) * 2);
		if (upd_list == NULL) {
			printf("Growing upd_list failed!\n");
			exit(300);
		}
		memset(&(upd_list[i]), 0, upd_list_size *
		       sizeof(struct mapd_upd_file));
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
		    upd_list[i].map.mmap != NULL &&
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

	pthread_rwlock_wrlock(&updlist_lock);
	i = MAPD_LIST_INIT_SIZE * sizeof(struct mapd_upd_file);
	upd_list = malloc(i);
	if (upd_list == NULL) {
		printf("Unable to initialize file cache\n");
		exit(200);
	}
	memset(upd_list, 0, i);
	pthread_rwlock_unlock(&updlist_lock);

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
