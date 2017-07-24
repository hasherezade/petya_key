#pragma once

#include <stdio.h>
#include <string.h>

#define SECTOR_SIZE 0x200

#define REDGREEN_ONION_SECTOR_NUM 54
#define GOLDEN_ONION_SECTOR_NUM 32

#define VICTIM_ID_OFFSET 0xa9
#define VICTIM_ID_MAXSIZE 100


bool is_infected(FILE *fp);

char* fetch_victim_id(FILE *fp, size_t onion_sector_num);
