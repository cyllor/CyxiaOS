/* Optional next-stage probe: real upstream libXau and target musl only. */
#include <X11/Xauth.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    char address[] = "cyxia";
    char number[] = "0";
    char name[] = "MIT-MAGIC-COOKIE-1";
    char secret[] = "probe-not-a-real-secret";
    Xauth original = {FamilyLocal, sizeof(address)-1, address, sizeof(number)-1,
                      number, sizeof(name)-1, name, sizeof(secret)-1, secret};
    FILE *file = fopen("/xau-probe.auth", "w+");
    if (!file || !XauWriteAuth(file, &original) || fflush(file) || fseek(file, 0, SEEK_SET)) {
        puts("XAU_PROBE FAIL write");
        return 1;
    }
    Xauth *readback = XauReadAuth(file);
    if (!readback || readback->family != original.family ||
        readback->address_length != original.address_length ||
        readback->number_length != original.number_length ||
        readback->name_length != original.name_length ||
        readback->data_length != original.data_length ||
        memcmp(readback->address, address, original.address_length) ||
        memcmp(readback->number, number, original.number_length) ||
        memcmp(readback->name, name, original.name_length) ||
        memcmp(readback->data, secret, original.data_length)) {
        puts("XAU_PROBE FAIL read");
        return 1;
    }
    XauDisposeAuth(readback);
    if (fclose(file)) return 1;
    puts("XAU_PROBE PASS");
    return 0;
}
