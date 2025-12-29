#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

#define MAX_SHARED_FILES 256

/* =========================
 * Shared file structures
 * ========================= */
typedef struct {
    char filename[256];
    uint64_t filesize;
    char filepath[512];
} FileInfo;

typedef struct {
    FileInfo files[MAX_SHARED_FILES];
    int count;
} SharedFileList;

extern SharedFileList g_shared_files;

/* =========================
 * Client state
 * ========================= */
typedef struct {
    uint32_t client_id;
    int p2p_port;
    int server_socket;
    int p2p_socket;
    char username[64];
    int is_logged_in;
    char shared_directory[256];
} ClientState;

typedef struct {
    uint32_t client_id;
    char ip_address[16];
    int port;
    char filename[256];
} PeerInfo;

extern ClientState g_client;

/* =========================
 * Network / protocol APIs
 * ========================= */
int connect_to_server(const char *ip, int port);
void disconnect_from_server(int sock);

int handle_login(int sock, const char *user, const char *pass);
int handle_register(int sock, const char *user, const char *pass);
int handle_sendinfo(int sock);

int handle_search(int sock,
                  const char *keyword,
                  PeerInfo *peers,
                  int max_peers);

int handle_publish(int sock, const char *filename, const char *filepath);
int handle_unpublish(int sock, const char *filename);

void handle_download(const char* peer_ip,
                     int peer_port,
                     const char* filename);

/* P2P internal */
int initiate_p2p_handshake(const char* peer_ip,
                           int peer_port,
                           const char* filename,
                           long *filesize_out);

void handle_download_request(int peer_sock,
                             const char* filename);

/* =========================
 * Session helpers
 * ========================= */
void send_client_info(void);
void client_logout(void);

/* =========================
 * Local index.txt management
 * ========================= */
int  load_shared_files(void);
void add_to_local_index(const char *filename, const char *filepath);
void remove_from_local_index(const char *filename);
int get_local_path(const char *filename, char *path_out);

#endif /* CLIENT_H */
