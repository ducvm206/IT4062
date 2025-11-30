// client_config.h
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define CONFIG_FILE "config.txt"

uint32_t generate_client_id();
bool load_client_id(uint32_t *id);
bool save_client_id(uint32_t id);

#endif