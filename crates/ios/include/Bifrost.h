#ifndef BIFROST_H
#define BIFROST_H
#include <stdbool.h>

typedef struct NativePeer NativePeer;
// All handle operations belong to one UI thread. Strings passed in are copied.
NativePeer *bifrost_peer_create(const char *configuration);
// Returns the latest changed state, or NULL. Free every returned JSON string.
char *bifrost_peer_poll(NativePeer *peer);
void bifrost_peer_approve(NativePeer *peer, bool allowed);
// Cancels networking and consumes the handle; async teardown owns its remaining state.
void bifrost_peer_free(NativePeer *peer);
void bifrost_string_free(char *string);
#endif
