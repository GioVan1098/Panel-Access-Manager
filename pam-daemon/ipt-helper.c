/*
 * ipt-helper — PAM privilege helper
 *
 * Install:   sudo install -m 755 ipt-helper /usr/lib/rofi-bridge/ipt-helper
 *            sudo setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper
 *
 * Usage:     ipt-helper <open|close|check>
 *   Reads port from ~/.config/rofi-bridge/config.toml
 *   Executes iptables via execv — no shell, no argument injection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#define CONFIG_REL   "/.config/rofi-bridge/config.toml"
#define MAX_PORT     65535
#define DEFAULT_PORT 7443

/* Locate iptables: /usr/sbin (Debian/Ubuntu) or /usr/bin (Arch/Fedora). */
static const char *find_iptables(void)
{
    static const char * const paths[] = {
        "/usr/sbin/iptables",
        "/usr/bin/iptables",
        NULL
    };
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

static int read_port(void)
{
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return DEFAULT_PORT;

    char path[512];
    snprintf(path, sizeof(path), "%s%s", home, CONFIG_REL);

    FILE *f = fopen(path, "r");
    if (!f) return DEFAULT_PORT;

    int port = DEFAULT_PORT;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int p;
        if (sscanf(line, "port = %d", &p) == 1 && p > 0 && p <= MAX_PORT) {
            port = p;
            break;
        }
    }
    fclose(f);
    return port;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: ipt-helper <open|close|check>\n");
        return 1;
    }

    const char *action = argv[1];
    if (strcmp(action, "open")  != 0 &&
        strcmp(action, "close") != 0 &&
        strcmp(action, "check") != 0) {
        fprintf(stderr, "ipt-helper: invalid action '%s'\n", action);
        return 1;
    }

    const char *iptables = find_iptables();
    if (!iptables) {
        fprintf(stderr, "ipt-helper: iptables not found in /usr/sbin or /usr/bin\n");
        return 1;
    }

    int port = read_port();
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    /*
     * execv replaces the process image — no shell, no metacharacters.
     * argv arrays are terminated by NULL.
     */
    if (strcmp(action, "open") == 0) {
        char *av[] = { (char *)iptables, "-I", "INPUT", "-p", "tcp",
                       "--dport", port_str, "-j", "ACCEPT", NULL };
        execv(iptables, av);
    } else if (strcmp(action, "close") == 0) {
        char *av[] = { (char *)iptables, "-D", "INPUT", "-p", "tcp",
                       "--dport", port_str, "-j", "ACCEPT", NULL };
        execv(iptables, av);
    } else {  /* check */
        char *av[] = { (char *)iptables, "-C", "INPUT", "-p", "tcp",
                       "--dport", port_str, "-j", "ACCEPT", NULL };
        execv(iptables, av);
    }

    fprintf(stderr, "ipt-helper: execv: %s\n", strerror(errno));
    return 1;
}
