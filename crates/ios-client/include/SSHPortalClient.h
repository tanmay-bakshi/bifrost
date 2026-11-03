#ifndef SSHPORTAL_CLIENT_H
#define SSHPORTAL_CLIENT_H
#include <stdbool.h>

typedef struct NativeClient NativeClient;
// All handle operations belong to one UI thread. Strings passed in are copied.
NativeClient *sshportal_client_create(const char *configuration);
// Returns the latest changed state, or NULL. Free every returned JSON string.
char *sshportal_client_poll(NativeClient *client);
void sshportal_client_approve(NativeClient *client, bool allowed);
// Cancels networking and consumes the handle; async teardown owns its remaining state.
void sshportal_client_free(NativeClient *client);
void sshportal_string_free(char *string);
#endif
