/* 
 * Simple cache DB, copypizded from gnutls manual with multithreaded
 * modifications
 */

#include <gnutls/gnutls.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "apds_cache_db.h"
#include "apds_main.h"

pthread_mutex_t cache_db_mut;

typedef struct {
	char session_id[MAX_SESSION_ID_SIZE];
	size_t session_id_size;
	char session_data[MAX_SESSION_DATA_SIZE];
	size_t session_data_size;
} CACHE;

static CACHE *cache_db;
static int cache_db_ptr = 0;

void cache_db_global_init() {
	/* allocate cache_db */
	cache_db = calloc (1, TLS_SESSION_CACHE * sizeof (CACHE));
	pthread_mutex_init(&cache_db_mut, NULL);
}

void cache_db_session_init(gnutls_session_t *session) {
	gnutls_db_set_retrieve_function(*session, cache_db_fetch);
	gnutls_db_set_remove_function(*session, cache_db_delete);
	gnutls_db_set_store_function(*session, cache_db_store);
	gnutls_db_set_ptr(*session, NULL);
}

void cache_db_deinit(void) {
	free(cache_db);
	cache_db = NULL;
	pthread_mutex_destroy(&cache_db_mut);
}

int cache_db_store(void *dbf, gnutls_datum_t key, gnutls_datum_t data) {
	if (cache_db == NULL)
		return -1;
	if (key.size > MAX_SESSION_ID_SIZE)
		return -1;
	if (data.size > MAX_SESSION_DATA_SIZE)
		return -1;
	pthread_mutex_lock(&cache_db_mut);
	memcpy (cache_db[cache_db_ptr].session_data, data.data, data.size);
	cache_db[cache_db_ptr].session_data_size = data.size;
	cache_db[cache_db_ptr].session_id_size = key.size;
	memcpy (cache_db[cache_db_ptr].session_id, key.data, key.size);
	cache_db_ptr++;
	cache_db_ptr %= TLS_SESSION_CACHE;
	pthread_mutex_unlock(&cache_db_mut);
	return 0;
}

gnutls_datum_t cache_db_fetch (void *dbf, gnutls_datum_t key) {
	gnutls_datum_t res = { NULL, 0 };
	int i;
	if (cache_db == NULL)
		return res;
	pthread_mutex_lock(&cache_db_mut);
	for (i = 0; i < TLS_SESSION_CACHE; i++) {
		if (key.size == cache_db[i].session_id_size &&
		    memcmp (key.data, cache_db[i].session_id, key.size) == 0) {

			res.size = cache_db[i].session_data_size;
			res.data = gnutls_malloc (res.size);
			if (res.data == NULL)
				break;
			memcpy (res.data, cache_db[i].session_data, res.size);
			break;
		}
	}

	pthread_mutex_unlock(&cache_db_mut);
	return res;
}

int cache_db_delete (void *dbf, gnutls_datum_t key) {
	int i;
	if (cache_db == NULL)
		return -1;
	for (i = 0; i < TLS_SESSION_CACHE; i++) {
		if (key.size == cache_db[i].session_id_size &&
		    memcmp (key.data, cache_db[i].session_id, key.size) == 0) {
			pthread_mutex_lock(&cache_db_mut);
      			cache_db[i].session_id_size = 0;
			cache_db[i].session_data_size = 0;
			pthread_mutex_unlock(&cache_db_mut);
			return 0;
		}
	}
	return -1;
}
