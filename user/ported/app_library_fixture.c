/* Install two entries on the regression guest's writable data volume. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

static int install(const char *path, const char *name, const char *exec) {
    FILE *file = fopen(path, "wx");
    if (!file) return -1;
    int written = fprintf(file,
        "[Desktop Entry]\nType=Application\nName=%s\nExec=%s\n"
        "Icon=com.system76.CosmicAppLibrary\nTerminal=false\nCategories=Utility;\n",
        name, exec);
    int closed = fclose(file);
    return written < 0 || closed < 0 ? -1 : 0;
}

int main(void) {
    const char *dirs[] = {"/.local", "/.local/share", "/.local/share/applications"};
    for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (mkdir(dirs[i], 0755) && errno != EEXIST) {
            perror(dirs[i]);
            return 1;
        }
    }
    if (install("/.local/share/applications/cyxia-amber.desktop", "Amber Diagnostic", "env-probe")
        || install("/.local/share/applications/cyxia-birch.desktop", "Birch Workspace",
                   "workspace-window-probe --app-library")) {
        perror("Install application library fixture");
        return 1;
    }
    puts("APP_LIBRARY_FIXTURE READY");
    return 0;
}
