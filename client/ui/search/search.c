#include "search.h"
#include "../interface.h"
#include "../../client.h"
#include "../dashboard/dashboard.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#define MAX_SEARCH_RESULTS 64

/* =========================
 * Widgets
 * ========================= */
static GtkWidget *window;
static GtkWidget *entry_search;
static GtkWidget *result_list;
static GtkWidget *status_label;

/* =========================
 * Helpers
 * ========================= */

static void clear_results(void)
{
    GtkListBoxRow *row;
    while ((row = gtk_list_box_get_row_at_index(
                GTK_LIST_BOX(result_list), 0))) {
        gtk_widget_destroy(GTK_WIDGET(row));
    }
}

/* =========================
 * Download callback
 * ========================= */

typedef struct {
    uint32_t client_id;
    char ip[16];
    int port;
    char filename[256];
} DownloadCtx;

static void on_download_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    DownloadCtx *ctx = (DownloadCtx *)data;

    char buf[256];
    snprintf(buf, sizeof(buf),
             "Downloading '%s' from %s:%d ...",
             ctx->filename, ctx->ip, ctx->port);

    gtk_label_set_text(GTK_LABEL(status_label), buf);

    printf("[UI] Download request → %s:%d (%s)\n",
           ctx->ip, ctx->port, ctx->filename);

    /* 🔥 DOWNLOAD THẬT */
    handle_download(ctx->ip, ctx->port, ctx->filename);

    gtk_label_set_text(GTK_LABEL(status_label),
                       "Download finished");
}

/* =========================
 * UI rows
 * ========================= */

static void add_header_row(void)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    GtkWidget *lbl_client = gtk_label_new("ClientID");
    GtkWidget *lbl_port   = gtk_label_new("Port");
    GtkWidget *lbl_file   = gtk_label_new("Filename");

    gtk_widget_set_size_request(lbl_client, 120, -1);
    gtk_widget_set_size_request(lbl_port, 80, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl_file), 0.0);

    gtk_box_pack_start(GTK_BOX(box), lbl_client, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lbl_port,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lbl_file,   TRUE,  TRUE,  0);

    gtk_container_add(GTK_CONTAINER(row), box);
    gtk_list_box_insert(GTK_LIST_BOX(result_list), row, -1);
}

static void add_result_row(PeerInfo *peer, const char *filename)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    char buf[64];

    /* ClientID */
    snprintf(buf, sizeof(buf), "%u", peer->client_id);
    GtkWidget *lbl_client = gtk_label_new(buf);
    gtk_widget_set_size_request(lbl_client, 120, -1);

    /* Port */
    snprintf(buf, sizeof(buf), "%d", peer->port);
    GtkWidget *lbl_port = gtk_label_new(buf);
    gtk_widget_set_size_request(lbl_port, 80, -1);

    /* Filename */
    GtkWidget *lbl_file = gtk_label_new(filename);
    gtk_label_set_xalign(GTK_LABEL(lbl_file), 0.0);

    /* Download button */
    GtkWidget *btn_download = gtk_button_new_with_label("Download");

    DownloadCtx *ctx = g_malloc(sizeof(DownloadCtx));
    ctx->client_id = peer->client_id;
    ctx->port = peer->port;
    strncpy(ctx->ip, peer->ip_address, sizeof(ctx->ip) - 1);
    strncpy(ctx->filename, filename, sizeof(ctx->filename) - 1);

    g_signal_connect(btn_download,
                     "clicked",
                     G_CALLBACK(on_download_clicked),
                     ctx);

    gtk_box_pack_start(GTK_BOX(box), lbl_client, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lbl_port,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lbl_file,   TRUE,  TRUE,  0);
    gtk_box_pack_end  (GTK_BOX(box), btn_download, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(row), box);
    gtk_list_box_insert(GTK_LIST_BOX(result_list), row, -1);
}

/* =========================
 * SEARCH
 * ========================= */

static void on_search_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;

    const char *keyword =
        gtk_entry_get_text(GTK_ENTRY(entry_search));

    if (!keyword || strlen(keyword) == 0)
        return;

    clear_results();
    add_header_row();

    gtk_label_set_text(GTK_LABEL(status_label), "Searching...");

    PeerInfo peers[MAX_SEARCH_RESULTS];
    memset(peers, 0, sizeof(peers));

    int count = handle_search(g_client.server_socket,
                              keyword,
                              peers,
                              MAX_SEARCH_RESULTS);

    if (count <= 0) {
        gtk_label_set_text(GTK_LABEL(status_label),
                           "No peers found");
        return;
    }

    for (int i = 0; i < count; i++) {
        add_result_row(&peers[i], keyword);
    }

    gtk_label_set_text(GTK_LABEL(status_label),
                       "Search completed");
    gtk_widget_show_all(result_list);
}

/* =========================
 * Navigation
 * ========================= */

static void on_return_clicked(GtkButton *btn, gpointer data)
{
    (void)btn;
    (void)data;

    gtk_widget_destroy(window);
    dashboard_show();
}

/* =========================
 * UI Builder
 * ========================= */

static GtkWidget* create_search_view(void)
{
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(root), 10);

    /* Search bar */
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    entry_search = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_search),
                                   "Enter filename to search...");

    GtkWidget *btn_search = gtk_button_new_with_label("Search");
    GtkWidget *btn_return = gtk_button_new_with_label("Dashboard");

    g_signal_connect(btn_search, "clicked",
                     G_CALLBACK(on_search_clicked), NULL);
    g_signal_connect(btn_return, "clicked",
                     G_CALLBACK(on_return_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(search_box), entry_search, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(search_box), btn_search, FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(search_box), btn_return, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), search_box, FALSE, FALSE, 0);

    /* Result list */
    GtkWidget *frame = gtk_frame_new("Search Results");

    result_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(result_list),
                                    GTK_SELECTION_NONE);

    gtk_container_add(GTK_CONTAINER(frame), result_list);
    gtk_box_pack_start(GTK_BOX(root), frame, TRUE, TRUE, 0);

    /* Status */
    status_label = gtk_label_new("Idle");
    gtk_widget_set_halign(status_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(root), status_label, FALSE, FALSE, 0);

    return root;
}

/* =========================
 * Public API
 * ========================= */

void search_show(void)
{
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Search Files");
    gtk_window_set_default_size(GTK_WINDOW(window), 650, 420);

    GtkWidget *view = create_search_view();
    gtk_container_add(GTK_CONTAINER(window), view);

    gtk_widget_show_all(window);
}


