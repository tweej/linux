// SPDX-License-Identifier: GPL-2.0

#include "binder_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>

#include <linux/limits.h>
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>

static const size_t BINDER_MMAP_SIZE = 64 * 1024;

static void binderfs_unmount(const char *mountpoint)
{
	if (umount2(mountpoint, MNT_DETACH))
		fprintf(stderr, "Failed to unmount binderfs at %s: %s\n",
			mountpoint, strerror(errno));
	else
		fprintf(stderr, "Binderfs unmounted: %s\n", mountpoint);

	if (rmdir(mountpoint))
		fprintf(stderr, "Failed to remove binderfs mount %s: %s\n",
			mountpoint, strerror(errno));
	else
		fprintf(stderr, "Binderfs mountpoint destroyed: %s\n", mountpoint);
}

int create_binderfs(struct binderfs_ctx *ctx, const char *name)
{
	int fd, ret, saved_errno;
	struct binderfs_device device = { 0 };

	/*
	 * P_tmpdir is set to "/tmp/" on Android platforms where Binder is most commonly used, but
	 * this path does not actually exist on Android. For Android we'll try using
	 * "/data/local/tmp" and P_tmpdir for non-Android platforms.
	 *
	 * This mount point should have a trailing '/' character, but mkdtemp requires that the last
	 * six characters (before the first null terminator) must be "XXXXXX". Manually append an
	 * additional null character in the string literal to allocate a character array of the
	 * correct final size, which we will replace with a '/' after successful completion of the
	 * mkdtemp call.
	 */
#ifdef __ANDROID__
	char binderfs_mntpt[] = "/data/local/tmp/binderfs_XXXXXX\0";
#else
	/* P_tmpdir may or may not contain a trailing '/' separator. We always append one here. */
	char binderfs_mntpt[] = P_tmpdir "/binderfs_XXXXXX\0";
#endif
	static const char BINDER_CONTROL_NAME[] = "binder-control";
	char device_path[strlen(binderfs_mntpt) + 1 + strlen(BINDER_CONTROL_NAME) + 1];

	if (mkdtemp(binderfs_mntpt) == NULL) {
		fprintf(stderr, "Failed to create binderfs mountpoint at %s: %s.\n",
			binderfs_mntpt, strerror(errno));
		return -1;
	}
	binderfs_mntpt[strlen(binderfs_mntpt)] = '/';
	fprintf(stderr, "Binderfs mountpoint created at %s\n", binderfs_mntpt);

	if (mount(NULL, binderfs_mntpt, "binder", 0, 0)) {
		perror("Could not mount binderfs");
		rmdir(binderfs_mntpt);
		return -1;
	}
	fprintf(stderr, "Binderfs mounted at %s\n", binderfs_mntpt);

	strncpy(device.name, name, sizeof(device.name));
	snprintf(device_path, sizeof(device_path), "%s%s", binderfs_mntpt, BINDER_CONTROL_NAME);
	fd = open(device_path, O_RDONLY | O_CLOEXEC);
	if (!fd) {
		fprintf(stderr, "Failed to open %s device", BINDER_CONTROL_NAME);
		binderfs_unmount(binderfs_mntpt);
		return -1;
	}

	ret = ioctl(fd, BINDER_CTL_ADD, &device);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (ret) {
		perror("Failed to allocate new binder device");
		binderfs_unmount(binderfs_mntpt);
		return -1;
	}

	fprintf(stderr, "Allocated new binder device with major %d, minor %d, and name %s at %s\n",
		device.major, device.minor, device.name, binderfs_mntpt);

	ctx->name = strdup(name);
	ctx->mountpoint = strdup(binderfs_mntpt);

	return 0;
}

void destroy_binderfs(struct binderfs_ctx *ctx)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s", ctx->mountpoint, ctx->name);

	if (unlink(path))
		fprintf(stderr, "Failed to unlink binder device %s: %s\n", path, strerror(errno));
	else
		fprintf(stderr, "Destroyed binder %s at %s\n", ctx->name, ctx->mountpoint);

	binderfs_unmount(ctx->mountpoint);

	free(ctx->name);
	free(ctx->mountpoint);
}

int open_binder(const struct binderfs_ctx *bfs_ctx, struct binder_ctx *ctx)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s", bfs_ctx->mountpoint, bfs_ctx->name);
	ctx->fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (ctx->fd < 0) {
		fprintf(stderr, "Error opening binder device %s: %s\n", path, strerror(errno));
		return -1;
	}

	ctx->memory = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_SHARED, ctx->fd, 0);
	if (ctx->memory == NULL) {
		perror("Error mapping binder memory");
		close(ctx->fd);
		ctx->fd = -1;
		return -1;
	}

	return 0;
}

void close_binder(struct binder_ctx *ctx)
{
	if (munmap(ctx->memory, BINDER_MMAP_SIZE))
		perror("Failed to unmap binder memory");
	ctx->memory = NULL;

	if (close(ctx->fd))
		perror("Failed to close binder");
	ctx->fd = -1;
}

int become_binder_context_manager(int binder_fd)
{
	return ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, 0);
}

int do_binder_write_read(int binder_fd, void *writebuf, binder_size_t writesize,
			 void *readbuf, binder_size_t readsize)
{
	int err;
	struct binder_write_read bwr = {
		.write_buffer = (binder_uintptr_t)writebuf,
		.write_size = writesize,
		.read_buffer = (binder_uintptr_t)readbuf,
		.read_size = readsize
	};

	do {
		if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) >= 0)
			err = 0;
		else
			err = -errno;
	} while (err == -EINTR);

	if (err < 0) {
		perror("BINDER_WRITE_READ");
		return -1;
	}

	if (bwr.write_consumed < writesize) {
		fprintf(stderr, "Binder did not consume full write buffer %llu %llu\n",
			bwr.write_consumed, writesize);
		return -1;
	}

	return bwr.read_consumed;
}

static const char *reply_string(int cmd)
{
	switch (cmd) {
	case BR_ERROR:
		return "BR_ERROR";
	case BR_OK:
		return "BR_OK";
	case BR_TRANSACTION_SEC_CTX:
		return "BR_TRANSACTION_SEC_CTX";
	case BR_TRANSACTION:
		return "BR_TRANSACTION";
	case BR_REPLY:
		return "BR_REPLY";
	case BR_ACQUIRE_RESULT:
		return "BR_ACQUIRE_RESULT";
	case BR_DEAD_REPLY:
		return "BR_DEAD_REPLY";
	case BR_TRANSACTION_COMPLETE:
		return "BR_TRANSACTION_COMPLETE";
	case BR_INCREFS:
		return "BR_INCREFS";
	case BR_ACQUIRE:
		return "BR_ACQUIRE";
	case BR_RELEASE:
		return "BR_RELEASE";
	case BR_DECREFS:
		return "BR_DECREFS";
	case BR_ATTEMPT_ACQUIRE:
		return "BR_ATTEMPT_ACQUIRE";
	case BR_NOOP:
		return "BR_NOOP";
	case BR_SPAWN_LOOPER:
		return "BR_SPAWN_LOOPER";
	case BR_FINISHED:
		return "BR_FINISHED";
	case BR_DEAD_BINDER:
		return "BR_DEAD_BINDER";
	case BR_CLEAR_DEATH_NOTIFICATION_DONE:
		return "BR_CLEAR_DEATH_NOTIFICATION_DONE";
	case BR_FAILED_REPLY:
		return "BR_FAILED_REPLY";
	case BR_FROZEN_REPLY:
		return "BR_FROZEN_REPLY";
	case BR_ONEWAY_SPAM_SUSPECT:
		return "BR_ONEWAY_SPAM_SUSPECT";
	default:
		return "Unknown";
	};
}

int expect_binder_reply(int32_t actual, int32_t expected)
{
	if (actual != expected) {
		fprintf(stderr, "Expected %s but received %s\n",
			reply_string(expected), reply_string(actual));
		return -1;
	}
	return 0;
}

