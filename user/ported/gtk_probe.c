/* Real GTK3 widgets for the static port's future guest acceptance test.
 * Building this executable does not demonstrate that it runs in CyxiaOS. */
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned clicks;
static gboolean drawn;
static GtkWidget *entry;
static GtkWidget *button;

static gboolean mapped(GtkWidget *window, GdkEvent *event, gpointer data)
{
    GtkAllocation bounds, entry_bounds, button_bounds;
    int x, y, ex, ey, bx, by;
    (void)event;
    (void)data;
    gtk_widget_get_allocation(window, &bounds);
    gtk_widget_get_allocation(entry, &entry_bounds);
    gtk_widget_get_allocation(button, &button_bounds);
    gdk_window_get_origin(gtk_widget_get_window(window), &x, &y);
    if (!gtk_widget_translate_coordinates(entry, window, 0, 0, &ex, &ey) ||
        !gtk_widget_translate_coordinates(button, window, 0, 0, &bx, &by))
        return FALSE;
    printf("GTK_PROBE WINDOW x=%d y=%d width=%d height=%d\n", x, y, bounds.width, bounds.height);
    printf("GTK_PROBE ENTRY x=%d y=%d width=%d height=%d\n", x + ex, y + ey, entry_bounds.width, entry_bounds.height);
    printf("GTK_PROBE BUTTON x=%d y=%d width=%d height=%d\n", x + bx, y + by, button_bounds.width, button_bounds.height);
    fflush(stdout);
    return FALSE;
}

static gboolean draw_complete(GtkWidget *widget, cairo_t *cr, gpointer data)
{
    (void)widget;
    (void)cr;
    (void)data;
    if (!drawn) {
        puts("GTK_PROBE DRAW");
        fflush(stdout);
        drawn = TRUE;
    }
    return FALSE;
}

static void text_changed(GtkEditable *editable, gpointer data)
{
    (void)data;
    printf("GTK_PROBE TEXT text=%s\n", gtk_entry_get_text(GTK_ENTRY(editable)));
    fflush(stdout);
}

static void clicked(GtkButton *button, gpointer data)
{
    char text[80];
    (void)button;
    ++clicks;
    snprintf(text, sizeof text, "Button clicks: %u", clicks);
    gtk_label_set_text(GTK_LABEL(data), text);
    printf("GTK_PROBE CLICK count=%u\n", clicks);
    fflush(stdout);
}

static gboolean finish_smoke(gpointer data)
{
    gtk_widget_destroy(GTK_WIDGET(data));
    return G_SOURCE_REMOVE;
}

int main(int argc, char **argv)
{
    unsigned long timeout_ms = 0;
    if (argc == 2 && strcmp(argv[1], "--smoke") == 0) {
        timeout_ms = 3000;
        argc = 1;
    } else if (argc == 3 && strcmp(argv[1], "--timeout-ms") == 0) {
        char *end;
        timeout_ms = strtoul(argv[2], &end, 10);
        if (*end || timeout_ms == 0 || timeout_ms > 600000)
            return 2;
        argc = 1;
    }
    if (!gtk_init_check(&argc, &argv)) {
        fputs("GTK_PROBE INIT_FAILED\n", stderr);
        return 1;
    }
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "CyxiaOS GTK 3");
    gtk_window_set_default_size(GTK_WINDOW(window), 440, 260);
    gtk_container_set_border_width(GTK_CONTAINER(window), 24);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_container_add(GTK_CONTAINER(window), box);
    GtkWidget *title = gtk_label_new("CyxiaOS - native GTK 3 widgets");
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
    entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Type here to test keyboard input");
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 0);
    g_signal_connect(entry, "changed", G_CALLBACK(text_changed), NULL);
    GtkWidget *status = gtk_label_new("Button clicks: 0");
    button = gtk_button_new_with_label("Test button");
    g_signal_connect(button, "clicked", G_CALLBACK(clicked), status);
    gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), status, FALSE, FALSE, 0);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(window, "map-event", G_CALLBACK(mapped), NULL);
    g_signal_connect_after(window, "draw", G_CALLBACK(draw_complete), NULL);
    gtk_widget_show_all(window);
    puts("GTK_PROBE READY");
    fflush(stdout);
    if (timeout_ms)
        g_timeout_add((guint)timeout_ms, finish_smoke, window);
    gtk_main();
    puts("GTK_PROBE EXIT");
    return 0;
}
