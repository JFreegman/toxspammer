/*  util.c
 *
 *
 *  Copyright (C) 2024 toxspammer All Rights Reserved.
 *
 *  This file is part of toxspammer.
 *
 *  toxspammer is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  toxspammer is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with toxspammer.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "util.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <tox/tox.h>

void sleep_thread(long int usec)
{
    struct timespec req;
    struct timespec rem;

    req.tv_sec = 0;
    req.tv_nsec = usec * 1000L;

    if (nanosleep(&req, &rem) == -1) {
        if (nanosleep(&rem, NULL) == -1) {
            fprintf(stderr, "nanosleep() returned -1\n");
        }
    }
}

time_t get_time(void)
{
    return time(NULL);
}

bool timed_out(time_t timestamp, time_t timeout)
{
    return timestamp + timeout <= get_time();
}

int hex_string_to_bin(const char *hex_string, size_t hex_len, char *output, size_t output_size)
{
    if (output_size == 0 || hex_len != output_size * 2) {
        return -1;
    }

    for (size_t i = 0; i < output_size; ++i) {
        sscanf(hex_string, "%2hhx", (unsigned char *) &output[i]);
        hex_string += 2;
    }

    return 0;
}

int tox_id_string_to_bin(const char *id_str, size_t id_str_length, uint8_t *id_bin, size_t id_bin_size)
{
    if (id_bin_size != TOX_ADDRESS_SIZE || id_str_length != TOX_ADDRESS_SIZE * 2) {
        return -1;
    }

    char tmp[3];
    uint32_t byte = 0;

    for (size_t i = 0; i < TOX_ADDRESS_SIZE; ++i) {
        tmp[0] = id_str[2 * i];
        tmp[1] = id_str[2 * i + 1];
        tmp[2] = 0;

        if (sscanf(tmp, "%02x", &byte) != 1) {
            return -1;
        }

        id_bin[i] = (uint8_t) byte;
    }

    return 0;
}
