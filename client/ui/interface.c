#include "interface.h"
#include "../client.h"
#include "auth/auth.h"
#include "dashboard/dashboard.h"
#include "search/search.h"

void interface_init(void) {
    show_auth_screen();
}

void show_auth_screen(void) {
    auth_show();
}

void show_dashboard_screen(void) {
    dashboard_show();
}

void interface_show_search(void) {
    search_show();
}




