/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SELFTEST_BINDER_UTIL_H
#define SELFTEST_BINDER_UTIL_H

#include <stdint.h>

#include <linux/android/binder.h>

struct binderfs_ctx {
	char *name;
	char *mountpoint;
};

struct binder_ctx {
	int fd;
	void *memory;
};

int create_binderfs(struct binderfs_ctx *ctx, const char *name);
void destroy_binderfs(struct binderfs_ctx *ctx);

int open_binder(const struct binderfs_ctx *bfs_ctx, struct binder_ctx *ctx);
void close_binder(struct binder_ctx *ctx);

int become_binder_context_manager(int binder_fd);

int do_binder_write_read(int binder_fd, void *writebuf, binder_size_t writesize,
			 void *readbuf, binder_size_t readsize);

int expect_binder_reply(int32_t actual, int32_t expected);
#endif
