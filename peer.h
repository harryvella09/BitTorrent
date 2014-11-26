#ifdef _SLEEP_
#define SLEEP sleep(5)
#else
#define SLEEP 
#endif

int server_func(bt_args_t *bt_args, char * info_hash, char *selfid, int clientno);
int client_func(bt_args_t *bt_args, char * info_hash, char *selfid, int clientno);
