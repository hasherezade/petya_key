#include "petya.h"

bool check_pattern(FILE *fp, size_t offset, const char *cmp_buf, size_t cmp_size)
{
    char out_buf[0x400] = { 0 };

    cmp_size = (cmp_size > sizeof(out_buf)) ? sizeof(out_buf) : cmp_size;

    fseek(fp, offset, SEEK_SET);
    size_t read = fread(out_buf, 1, cmp_size, fp);

    if (read != cmp_size) {
        printf("Error, read = %d\n", read);
        return false;
    }

    if (memcmp(out_buf, cmp_buf, cmp_size-1) == 0) {
        return true;
    }
    return false;
}

bool is_infected(FILE *fp)
{
    char Bootloader[] = \
    "\xfa\x66\x31\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00\x7c\xfb\x88\x16";

    const size_t bootloader_offset = 0;
    bool has_bootloader = check_pattern(fp, bootloader_offset, Bootloader, sizeof(Bootloader));
    if (has_bootloader) printf("[+] Petya bootloader detected!\n");

    return has_bootloader;
}

bool check_onion_sector(FILE *fp, size_t onion_sector_num)
{
    char http_pattern[] = "http://";
    size_t pattern_len = strlen(http_pattern);
    size_t http_offset = onion_sector_num * SECTOR_SIZE + HTTP_OFFSET;
    bool has_http = check_pattern(fp, http_offset, http_pattern, pattern_len);
    if (has_http) {
        printf("[+] Petya http address detected!\n");
        return has_http;
    }
    http_offset = onion_sector_num * SECTOR_SIZE + HTTP_OFFSET_RED;
    has_http = check_pattern(fp, http_offset, http_pattern, pattern_len);
    if (has_http) {
        printf("[+] Petya http address detected!\n");
    }
    return has_http;
}

char* fetch_data(FILE *fp, const size_t offset, const size_t in_size)
{
    char* in_buf = new char[in_size];
    memset(in_buf, 0, in_size);
    fseek(fp, offset, SEEK_SET);
    size_t read = fread(in_buf, 1, in_size, fp);
    if (read != in_size) {
        printf("Error, read = %d\n", read);
        return NULL;
    }
    return in_buf;
}

char* fetch_victim_id(FILE *fp, size_t onion_sector_num)
{
    if (!check_onion_sector(fp, onion_sector_num)) {
        return NULL;
    }
    size_t offset = onion_sector_num * SECTOR_SIZE + VICTIM_ID_OFFSET;
    char *data = fetch_data(fp, offset, VICTIM_ID_MAXSIZE);
    if (strlen(data) == 0) {
        delete []data;
        data = NULL;
    }
    return data;
}


