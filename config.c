#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "config.h"

// -----------------------------------------------------------
// Generate 32-bit unsigned random ID
// -----------------------------------------------------------
uint32_t generate_client_id() {
    srand((unsigned)time(NULL));
    uint32_t id = ((uint32_t)rand() << 16) | (uint32_t)rand();
    if (id == 0) id = 1; // tránh ID = 0
    return id;
}

// -----------------------------------------------------------
// Load ClientID from config.txt
// Return true if file exists and ID loaded
// -----------------------------------------------------------
bool load_client_id(uint32_t *id) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp)
        return false;

    if (fscanf(fp, "%u", id) != 1) {
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

// -----------------------------------------------------------
// Save ClientID to config.txt
// -----------------------------------------------------------
bool save_client_id(uint32_t id) {
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp)
        return false;

    fprintf(fp, "%u\n", id);
    fclose(fp);

    return true;
}