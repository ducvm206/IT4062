// client_config.h
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define CONFIG_FILE "config.txt"
#define DB_HOST "localhost"
#define DB_USER "p2p_user"
#define DB_PASS "p2p_password"
#define DB_NAME "p2p_db"
#define DB_PORT 3306

uint32_t generate_client_id();
bool load_client_id(uint32_t *id);
bool save_client_id(uint32_t id);

#endif