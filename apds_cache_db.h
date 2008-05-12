/*
 * Cache handling is easy
 */

void cache_db_global_init();
void cache_db_session_init(gnutls_session_t *session);
void cache_db_deinit(void);
gnutls_datum_t cache_db_fetch (void *dbf, gnutls_datum_t key);
int cache_db_store(void *dbf, gnutls_datum_t key, gnutls_datum_t data);
int cache_db_delete (void *dbf, gnutls_datum_t key);
