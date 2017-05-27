#define SETPTR(ptr, val)  \
    do {                  \
        if((ptr) != NULL) \
            free((ptr));  \
        ptr = (val);      \
    } while(0);

#define SETPTR_cJSON(ptr, val)   \
    do {                         \
        if((ptr) != NULL)        \
            cJSON_Delete((ptr)); \
        ptr = (val);             \
    } while(0);
