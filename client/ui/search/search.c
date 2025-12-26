#include "search.h"
#include <gtk/gtk.h>

void search_show(void) {
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Search");
    gtk_window_set_default_size(GTK_WINDOW(win), 400, 300);

    GtkWidget *label = gtk_label_new("Search screen (TODO)");
    gtk_container_add(GTK_CONTAINER(win), label);

    gtk_widget_show_all(win);
}
