#ifndef APDS_FILE_CACHE_H
#define APDS_FILE_CACHE_H 1

#include <pthread.h>

struct upd_map {
	ssize_t size;
	void *mmap;
};

struct mapd_upd_file {
	struct upd_map map;
	int fd;
	char *name;
	pthread_rwlock_t lock;
};

struct upd_map get_upd_map(const char *fname);
void release_upd_file(struct upd_map upf);
void *apds_fcache_thread(void *smth);

#define MAPD_LIST_INIT_SIZE 32
#define UPD_LIST_SIZE (upd_list_size * sizeof(struct mapd_upd_file))

#endif
