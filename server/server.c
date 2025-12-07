#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../config.h"
#include <pthread.h>

// Windows networking
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Windows threading + sleep
#include <windows.h>

// Database libraries
#include <sqlite3.h>
#include <openssl/sha.h>   // For hashing passwords

// =============================================================================
// CONSTANTS
// =============================================================================

#define SERVER_PORT 8000
#define P2P_PORT 6000
#define BUFF_SIZE 8192
#define MAX_SHARED_FILES 256
#define MAX_CLIENTS 128
#define MAX_TOTAL_FILES 4096  // Maximum total files in system

// =============================================================================
// STRUCTURES AND TYPE DEFINITIONS
// =============================================================================

// Structure for session information
typedef struct {
    SOCKET socket_fd;
    struct sockaddr_in client_addr;

    int account_id;          // FK → accounts.account_id
    uint32_t client_id;      // ClientID sent via SENDINFO

    int is_logged_in;
    int is_active;
    time_t last_active;
} Session;

// Information about a client's P2P connection details
typedef struct {
    uint32_t client_id;
    char ip_address[16];
    int p2p_port;
    Session *session;
} ClientConnection;

// Server's file index entry
typedef struct {
    int file_id;           // DB primary key
    char filename[256];

    uint32_t client_id;
    char ip_address[16];
    int port;

    uint64_t filesize;
    time_t published_time;
} FileIndexEntry;

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

// Session management (runtime only)
Session sessions[MAX_CLIENTS];
int session_count = 0;
pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Client connection mapping (runtime only)
ClientConnection client_connections[MAX_CLIENTS];
int connection_count = 0;
pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;

// Database handle
sqlite3 *g_db = NULL;

// =============================================================================
// MESSAGE HANDLING FUNCTIONS
// =============================================================================

// Send all data in buffer
// returns: 0 on success, -1 on error
// Parameters: socket_fd - socket file descriptor
//             buffer - data buffer to send
//             length - length of data to send
int send_all(SOCKET socket_fd, const char *buffer, int length) {
    int total_sent = 0;     // Total bytes sent
    int bytes_left = length;
    int sent;

    // Keep sending until all data is sent
    while (total_sent < length) {
        sent = send(socket_fd,
                    buffer + total_sent,
                    bytes_left,
                    0);

        if (sent == SOCKET_ERROR) {
            return -1;
        }

        total_sent += sent;
        bytes_left -= sent;
    }

    return 0;
}

// Send response to client
void send_response(SOCKET socket_fd, const char *response) {
    send_all(socket_fd, response, (int)strlen(response));
}

void process_request(Session *session, char *request) {
    // Remove trailing "\r\n"
    int len = strlen(request);
    if (len >= 2 && request[len-2] == '\r' && request[len-1] == '\n') {
        request[len-2] = '\0';
    }

    // Parse command and arguments
    char command[20];
    char argument[BUFF_SIZE];
    memset(argument, 0, sizeof(argument));

    // Parse command
    if (sscanf(request, "%s %[^\r\n]", command, argument) < 1) {
        send_response(session->socket_fd, "300\r\n");
        return;
    }

    // Handle REGISTER command
    if (strcmp(command, "REGISTER") == 0) {
        char username[64], password[64], password_hash[65];

        if (sscanf(argument, "%63s %63s", username, password) != 2) {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        if (strlen(password) < 6) {
            send_response(session->socket_fd, "400\r\n");
            return;
        }

        sha256(password, password_hash);

        sqlite3_stmt *stmt;
        const char *sql =
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?);";

        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            send_response(session->socket_fd, "400\r\n");
            return;
        }

        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            send_response(session->socket_fd, "400\r\n");
            return;
        }

        sqlite3_finalize(stmt);
        send_response(session->socket_fd, "101\r\n");
    }

    // Handle LOGIN command
    else if (strcmp(command, "LOGIN") == 0) {
        char username[64], password[64], password_hash[65];

        if (sscanf(argument, "%63s %63s", username, password) != 2) {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        sha256(password, password_hash);

        sqlite3_stmt *stmt;
        const char *sql =
            "SELECT account_id FROM accounts WHERE username=? AND password_hash=?;";

        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            session->account_id = sqlite3_column_int(stmt, 0);
            session->is_logged_in = 1;
            send_response(session->socket_fd, "102\r\n");
        } else {
            send_response(session->socket_fd, "401\r\n");
        }

        sqlite3_finalize(stmt);
    }

    // Handle SENDINFO command
    else if (strcmp(command, "SENDINFO") == 0) {
        if (!session->is_logged_in) {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        uint32_t client_id;
        int port;
        char ip[16];

        sscanf(argument, "%u %d", &client_id, &port);
        inet_ntop(AF_INET, &session->client_addr.sin_addr, ip, sizeof(ip));

        session->client_id = client_id;

        sqlite3_stmt *stmt;
        const char *sql =
            "INSERT OR REPLACE INTO clients (client_id, account_id, ip_address, port) "
            "VALUES (?, ?, ?, ?);";

        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, client_id);
        sqlite3_bind_int(stmt, 2, session->account_id);
        sqlite3_bind_text(stmt, 3, ip, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, port);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        send_response(session->socket_fd, "103\r\n");
    }


    // Handle PUBLISH command
    else if (strcmp(command, "PUBLISH") == 0) {
        uint32_t client_id;
        char filename[256];

        sscanf(argument, "%u %255s", &client_id, filename);

        sqlite3_stmt *stmt;
        const char *sql =
            "INSERT INTO files (client_id, filename, filesize) VALUES (?, ?, 0);";

        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, client_id);
        sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        send_response(session->socket_fd, "201\r\n");
    }

    // Handle UNPUBLISH command
    else if (strcmp(command, "UNPUBLISH") == 0) {
        if (!session->is_logged_in) {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        char filename[256];

        if (sscanf(argument, "%255s", filename) != 1) {
            send_response(session->socket_fd, "300\r\n");
            return;
        }

        sqlite3_stmt *stmt;
        const char *sql =
            "UPDATE files SET is_active = 0 "
            "WHERE filename = ? AND client_id = ? AND is_active = 1;";

        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            send_response(session->socket_fd, "500\r\n");
            return;
        }

        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, session->client_id);

        int rc = sqlite3_step(stmt);
        int rows_affected = sqlite3_changes(g_db);

        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE || rows_affected == 0) {
            // File not found OR not owned by this client
            send_response(session->socket_fd, "404\r\n");
            return;
        }

        send_response(session->socket_fd, "202\r\n");
        printf("[INFO] File unpublished: %s (ClientID=%u)\n",
            filename, session->client_id);
    }

    // Handle SEARCH command
    else if (strcmp(command, "SEARCH") == 0) {
        char filename[256];

        sscanf(argument, "%255s", filename);

        sqlite3_stmt *stmt;
        const char *sql =
            "SELECT c.ip_address, c.port, f.client_id "
            "FROM files f JOIN clients c ON f.client_id=c.client_id "
            "WHERE f.filename=?;";

        sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);

        char response[BUFF_SIZE] = "210\r\n";
        int found = 0;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            char line[128];
            snprintf(line, sizeof(line), "%s %d %u\r\n",
                    sqlite3_column_text(stmt, 0),
                    sqlite3_column_int(stmt, 1),
                    sqlite3_column_int(stmt, 2));
            strcat(response, line);
        }

        sqlite3_finalize(stmt);

        if (!found) {
            send_response(session->socket_fd, "404\r\n");
            return;
        }

        send_response(session->socket_fd, response);
    }

    // Handle LOGOUT command
    else if (strcmp(command, "LOGOUT") == 0) {
        if (!session->is_logged_in) {
            send_response(session->socket_fd, "403\r\n");
            return;
        }

        sqlite3_stmt *stmt;

        // Mark client inactive
        const char *sql_client =
            "UPDATE clients SET is_active = 0 WHERE client_id = ?;";

        if (sqlite3_prepare_v2(g_db, sql_client, -1, &stmt, NULL) != SQLITE_OK) {
            send_response(session->socket_fd, "500\r\n");
            return;
        }

        sqlite3_bind_int(stmt, 1, session->client_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Mark all files from this client inactive
        const char *sql_files =
            "UPDATE files SET is_active = 0 WHERE client_id = ?;";

        if (sqlite3_prepare_v2(g_db, sql_files, -1, &stmt, NULL) != SQLITE_OK) {
            send_response(session->socket_fd, "500\r\n");
            return;
        }

        sqlite3_bind_int(stmt, 1, session->client_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Clear runtime session state
        pthread_mutex_lock(&session_mutex);

        session->is_logged_in = 0;
        session->account_id  = -1;
        session->client_id   = 0;

        pthread_mutex_unlock(&session_mutex);

        send_response(session->socket_fd, "104\r\n");
        printf("[INFO] Client logged out (ClientID=%u)\n", session->client_id);
    }
}
// =============================================================================
// DATABASE FUNCTIONS
// =============================================================================

// Read schema.sql file into a string
char *read_sql_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *sql = malloc(size + 1);
    if (!sql) {
        fclose(f);
        return NULL;
    }

    fread(sql, 1, size, f);
    sql[size] = '\0';
    fclose(f);

    return sql;
}

// Initialize SQLite database
// returns: 0 on success, -1 on error
int init_database(void) {
    int rc;

    // Open (or create) SQLite database file
    rc = sqlite3_open("p2p.db", &g_db);
    if (rc != SQLITE_OK) {
        printf("[DB] Cannot open database: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Read SQL schema from file
    char *sql = read_sql_file("database/schema.sql");
    if (!sql) {
        printf("[DB] Cannot read database/schema.sql\n");
        return -1;
    }

    // Execute schema SQL to initialize tables
    char *errmsg = NULL;
    rc = sqlite3_exec(g_db, sql, NULL, NULL, &errmsg);
    free(sql);

    if (rc != SQLITE_OK) {
        printf("[DB] SQL execution error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    printf("[DB] Database initialized successfully\n");
    return 0;
}

// Encrypt password using SHA-256
void sha256(const char *input, char output[65]) {
    // Plain text input
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Generate SHA-256 hash from input
    SHA256((unsigned char*)input, strlen(input), hash);

    // Convert hash to hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[64] = '\0';
}



