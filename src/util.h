/*  util.h
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

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Sleeps the calling thread for `usec` nanoseconds. */
void sleep_thread(long int usec);

/* Returns the current unix time. */
time_t get_time(void);

/* Returns true if timestamp has timed out according to timeout value. */
bool timed_out(time_t timestamp, time_t timeout);

/*
 * Converts a hexidecimal string of length hex_len to binary format and puts the result in output.
 * output_size must be exactly half of hex_len.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int hex_string_to_bin(const char *hex_string, size_t hex_len, char *output, size_t output_size);

/*
 * Converts a Tox ID string into binary format and puts the result in id_bin. id_bin_size
 * must be exactly TOX_ADDRESS_SIZE, and id_str_length must be exactly twice as large as
 * that.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int tox_id_string_to_bin(const char *id_str, size_t id_str_length, uint8_t *id_bin, size_t id_bin_size);

#endif  /* UTIL_H */
