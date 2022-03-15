// SPDX-License-Identifier: GPL-2.0

/*
 * These tests verify that the cgroup GPU memory charge is transferred correctly when a dmabuf is
 * passed between processes in two different cgroups and the sender specifies
 * BINDER_FD_FLAG_XFER_CHARGE or BINDER_FDA_FLAG_XFER_CHARGE in the binder transaction data
 * containing the dmabuf file descriptor.
 *
 * The parent test process becomes the binder context manager, then forks a child who initiates a
 * transaction with the context manager by specifying a target of 0. The context manager reply
 * contains a dmabuf file descriptor (or an array of one file descriptor) which was allocated by the
 * parent, but should be charged to the child cgroup after the binder transaction.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "binder_util.h"
#include "../../../cgroup/cgroup_util.h"
#include "../../../kselftest.h"
#include "../../../kselftest_harness.h"

#include <linux/limits.h>
#include <linux/dma-heap.h>
#include <linux/android/binder.h>

#define UNUSED(x) ((void)(x))

static const unsigned int BINDER_CODE = 8675309; /* Any number will work here */

struct cgroup_ctx {
	char *root;
	char *source;
	char *dest;
};

void destroy_cgroups(struct __test_metadata *_metadata, struct cgroup_ctx *ctx)
{
	if (ctx->source != NULL) {
		TH_LOG("Destroying cgroup: %s", ctx->source);
		rmdir(ctx->source);
		free(ctx->source);
	}

	if (ctx->dest != NULL) {
		TH_LOG("Destroying cgroup: %s", ctx->dest);
		rmdir(ctx->dest);
		free(ctx->dest);
	}

	free(ctx->root);
	ctx->root = ctx->source = ctx->dest = NULL;
}

struct cgroup_ctx create_cgroups(struct __test_metadata *_metadata)
{
	struct cgroup_ctx ctx = {0};
	char root[PATH_MAX], *tmp;
	static const char template[] = "/gpucg_XXXXXX";

	if (cg_find_unified_root(root, sizeof(root))) {
		TH_LOG("Could not find cgroups root");
		return ctx;
	}

	if (cg_read_strstr(root, "cgroup.controllers", "gpu")) {
		TH_LOG("Could not find GPU controller");
		return ctx;
	}

	if (cg_write(root, "cgroup.subtree_control", "+gpu")) {
		TH_LOG("Could not enable GPU controller");
		return ctx;
	}

	ctx.root = strdup(root);

	snprintf(root, sizeof(root), "%s/%s", ctx.root, template);
	tmp = mkdtemp(root);
	if (tmp == NULL) {
		TH_LOG("%s - Could not create source cgroup", strerror(errno));
		destroy_cgroups(_metadata, &ctx);
		return ctx;
	}
	ctx.source = strdup(tmp);

	snprintf(root, sizeof(root), "%s/%s", ctx.root, template);
	tmp = mkdtemp(root);
	if (tmp == NULL) {
		TH_LOG("%s - Could not create destination cgroup", strerror(errno));
		destroy_cgroups(_metadata, &ctx);
		return ctx;
	}
	ctx.dest = strdup(tmp);

	TH_LOG("Created cgroups: %s %s", ctx.source, ctx.dest);

	return ctx;
}

int dmabuf_heap_alloc(int fd, size_t len, int *dmabuf_fd)
{
	struct dma_heap_allocation_data data = {
		.len = len,
		.fd = 0,
		.fd_flags = O_RDONLY | O_CLOEXEC,
		.heap_flags = 0,
	};
	int ret;

	if (!dmabuf_fd)
		return -EINVAL;

	ret = ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &data);
	if (ret < 0)
		return ret;
	*dmabuf_fd = (int)data.fd;
	return ret;
}

/* The system heap is known to export dmabufs with support for cgroup tracking */
int alloc_dmabuf_from_system_heap(struct __test_metadata *_metadata, size_t bytes)
{
	int heap_fd = -1, dmabuf_fd = -1;
	static const char * const heap_path = "/dev/dma_heap/system";

	heap_fd = open(heap_path, O_RDONLY);
	if (heap_fd < 0) {
		TH_LOG("%s - open %s failed!\n", strerror(errno), heap_path);
		return -1;
	}

	if (dmabuf_heap_alloc(heap_fd, bytes, &dmabuf_fd))
		TH_LOG("dmabuf allocation failed! - %s", strerror(errno));
	close(heap_fd);

	return dmabuf_fd;
}

int binder_request_dmabuf(int binder_fd)
{
	int ret;

	/*
	 * We just send an empty binder_buffer_object to initiate a transaction
	 * with the context manager, who should respond with a single dmabuf
	 * inside a binder_fd_array_object or a binder_fd_object.
	 */

	struct binder_buffer_object bbo = {
		.hdr.type = BINDER_TYPE_PTR,
		.flags = 0,
		.buffer = 0,
		.length = 0,
		.parent = 0, /* No parent */
		.parent_offset = 0 /* No parent */
	};

	binder_size_t offsets[] = {0};

	struct {
		int32_t cmd;
		struct binder_transaction_data btd;
	} __attribute__((packed)) bc = {
		.cmd = BC_TRANSACTION,
		.btd = {
			.target = { 0 },
			.cookie = 0,
			.code = BINDER_CODE,
			.flags = TF_ACCEPT_FDS, /* We expect a FD/FDA in the reply */
			.data_size = sizeof(bbo),
			.offsets_size = sizeof(offsets),
			.data.ptr = {
				(binder_uintptr_t)&bbo,
				(binder_uintptr_t)offsets
			}
		},
	};

	struct {
		int32_t reply_noop;
	} __attribute__((packed)) br;

	ret = do_binder_write_read(binder_fd, &bc, sizeof(bc), &br, sizeof(br));
	if (ret >= sizeof(br) && expect_binder_reply(br.reply_noop, BR_NOOP)) {
		return -1;
	} else if (ret < sizeof(br)) {
		fprintf(stderr, "Not enough bytes in binder reply %d\n", ret);
		return -1;
	}
	return 0;
}

int send_dmabuf_reply_fda(int binder_fd, struct binder_transaction_data *tr, int dmabuf_fd)
{
	int ret;
	/*
	 * The trailing 0 is to achieve the necessary alignment for the binder
	 * buffer_size.
	 */
	int fdarray[] = { dmabuf_fd, 0 };

	struct binder_buffer_object bbo = {
		.hdr.type = BINDER_TYPE_PTR,
		.flags = 0,
		.buffer = (binder_uintptr_t)fdarray,
		.length = sizeof(fdarray),
		.parent = 0, /* No parent */
		.parent_offset = 0 /* No parent */
	};

	struct binder_fd_array_object bfdao = {
		.hdr.type = BINDER_TYPE_FDA,
		.flags = BINDER_FDA_FLAG_XFER_CHARGE,
		.num_fds = 1,
		.parent = 0, /* The binder_buffer_object */
		.parent_offset = 0 /* FDs follow immediately */
	};

	uint64_t sz = sizeof(fdarray);
	uint8_t data[sizeof(sz) + sizeof(bbo) + sizeof(bfdao)];
	binder_size_t offsets[] = {sizeof(sz), sizeof(sz)+sizeof(bbo)};

	memcpy(data,                            &sz, sizeof(sz));
	memcpy(data + sizeof(sz),               &bbo, sizeof(bbo));
	memcpy(data + sizeof(sz) + sizeof(bbo), &bfdao, sizeof(bfdao));

	struct {
		int32_t cmd;
		struct binder_transaction_data_sg btd;
	} __attribute__((packed)) bc = {
		.cmd = BC_REPLY_SG,
		.btd.transaction_data = {
			.target = { tr->target.handle },
			.cookie = tr->cookie,
			.code = BINDER_CODE,
			.flags = 0,
			.data_size = sizeof(data),
			.offsets_size = sizeof(offsets),
			.data.ptr = {
				(binder_uintptr_t)data,
				(binder_uintptr_t)offsets
			}
		},
		.btd.buffers_size = sizeof(fdarray)
	};

	struct {
		int32_t reply_noop;
	} __attribute__((packed)) br;

	ret = do_binder_write_read(binder_fd, &bc, sizeof(bc), &br, sizeof(br));
	if (ret >= sizeof(br) && expect_binder_reply(br.reply_noop, BR_NOOP)) {
		return -1;
	} else if (ret < sizeof(br)) {
		fprintf(stderr, "Not enough bytes in binder reply %d\n", ret);
		return -1;
	}
	return 0;
}

int send_dmabuf_reply_fd(int binder_fd, struct binder_transaction_data *tr, int dmabuf_fd)
{
	int ret;

	struct binder_fd_object bfdo = {
		.hdr.type = BINDER_TYPE_FD,
		.flags = BINDER_FD_FLAG_XFER_CHARGE,
		.fd = dmabuf_fd
	};

	binder_size_t offset = 0;

	struct {
		int32_t cmd;
		struct binder_transaction_data btd;
	} __attribute__((packed)) bc = {
		.cmd = BC_REPLY,
		.btd = {
			.target = { tr->target.handle },
			.cookie = tr->cookie,
			.code = BINDER_CODE,
			.flags = 0,
			.data_size = sizeof(bfdo),
			.offsets_size = sizeof(offset),
			.data.ptr = {
				(binder_uintptr_t)&bfdo,
				(binder_uintptr_t)&offset
			}
		}
	};

	struct {
		int32_t reply_noop;
	} __attribute__((packed)) br;

	ret = do_binder_write_read(binder_fd, &bc, sizeof(bc), &br, sizeof(br));
	if (ret >= sizeof(br) && expect_binder_reply(br.reply_noop, BR_NOOP)) {
		return -1;
	} else if (ret < sizeof(br)) {
		fprintf(stderr, "Not enough bytes in binder reply %d\n", ret);
		return -1;
	}
	return 0;
}

struct binder_transaction_data *binder_wait_for_transaction(int binder_fd,
							    uint32_t *readbuf,
							    size_t readsize)
{
	static const int MAX_EVENTS = 1, EPOLL_WAIT_TIME_MS = 3 * 1000;
	struct binder_reply {
		int32_t reply0;
		int32_t reply1;
		struct binder_transaction_data btd;
	} *br;
	struct binder_transaction_data *ret = NULL;
	struct epoll_event events[MAX_EVENTS];
	int epoll_fd, num_events, readcount;
	uint32_t bc[] = { BC_ENTER_LOOPER };

	do_binder_write_read(binder_fd, &bc, sizeof(bc), NULL, 0);

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd == -1) {
		perror("epoll_create");
		return NULL;
	}

	events[0].events = EPOLLIN;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &events[0])) {
		perror("epoll_ctl add");
		goto err_close;
	}

	num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_WAIT_TIME_MS);
	if (num_events < 0) {
		perror("epoll_wait");
		goto err_ctl;
	} else if (num_events == 0) {
		fprintf(stderr, "No events\n");
		goto err_ctl;
	}

	readcount = do_binder_write_read(binder_fd, NULL, 0, readbuf, readsize);
	fprintf(stderr, "Read %d bytes from binder\n", readcount);

	if (readcount < (int)sizeof(struct binder_reply)) {
		fprintf(stderr, "read_consumed not large enough\n");
		goto err_ctl;
	}

	br = (struct binder_reply *)readbuf;
	if (expect_binder_reply(br->reply0, BR_NOOP))
		goto err_ctl;

	if (br->reply1 == BR_TRANSACTION) {
		if (br->btd.code == BINDER_CODE)
			ret = &br->btd;
		else
			fprintf(stderr, "Received transaction with unexpected code: %u\n",
				br->btd.code);
	} else {
		expect_binder_reply(br->reply1, BR_TRANSACTION_COMPLETE);
	}

err_ctl:
	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, NULL))
		perror("epoll_ctl del");
err_close:
	close(epoll_fd);
	return ret;
}

static int child_request_dmabuf_transfer(const char *cgroup, void *arg)
{
	UNUSED(cgroup);
	int ret = -1;
	uint32_t readbuf[32];
	struct binderfs_ctx bfs_ctx = *(struct binderfs_ctx *)arg;
	struct binder_ctx b_ctx;

	fprintf(stderr, "Child PID: %d\n", getpid());

	if (open_binder(&bfs_ctx, &b_ctx)) {
		fprintf(stderr, "Child unable to open binder\n");
		return -1;
	}

	if (binder_request_dmabuf(b_ctx.fd))
		goto err;

	/* The child must stay alive until the binder reply is received */
	if (binder_wait_for_transaction(b_ctx.fd, readbuf, sizeof(readbuf)) == NULL)
		ret = 0;

	/*
	 * We don't close the received dmabuf here so that the parent can
	 * inspect the cgroup gpu memory charges to verify the charge transfer
	 * completed successfully.
	 */
err:
	close_binder(&b_ctx);
	fprintf(stderr, "Child done\n");
	return ret;
}

static const char * const GPUMEM_FILENAME = "gpu.memory.current";
static const size_t ONE_MiB = 1024 * 1024;

FIXTURE(fix) {
	int dmabuf_fd;
	struct binderfs_ctx bfs_ctx;
	struct binder_ctx b_ctx;
	struct cgroup_ctx cg_ctx;
	struct binder_transaction_data *tr;
	pid_t child_pid;
};

FIXTURE_SETUP(fix)
{
	long memsize;
	uint32_t readbuf[32];
	struct flat_binder_object *fbo;
	struct binder_buffer_object *bbo;

	if (geteuid() != 0)
		ksft_exit_skip("Need to be root to mount binderfs\n");

	if (create_binderfs(&self->bfs_ctx, "testbinder"))
		ksft_exit_skip("The Android binderfs filesystem is not available\n");

	self->cg_ctx = create_cgroups(_metadata);
	if (self->cg_ctx.root == NULL) {
		destroy_binderfs(&self->bfs_ctx);
		ksft_exit_skip("cgroup v2 isn't mounted\n");
	}

	ASSERT_EQ(cg_enter_current(self->cg_ctx.source), 0) {
		TH_LOG("Could not move parent to cgroup: %s", self->cg_ctx.source);
	}

	self->dmabuf_fd = alloc_dmabuf_from_system_heap(_metadata, ONE_MiB);
	ASSERT_GE(self->dmabuf_fd, 0);
	TH_LOG("Allocated dmabuf");

	memsize = cg_read_key_long(self->cg_ctx.source, GPUMEM_FILENAME, "system-heap");
	ASSERT_EQ(memsize, ONE_MiB) {
		TH_LOG("GPU memory used after allocation: %ld but it should be %lu",
		       memsize, (unsigned long)ONE_MiB);
	}

	ASSERT_EQ(open_binder(&self->bfs_ctx, &self->b_ctx), 0) {
		TH_LOG("Parent unable to open binder");
	}
	TH_LOG("Opened binder at %s/%s", self->bfs_ctx.mountpoint, self->bfs_ctx.name);

	ASSERT_EQ(become_binder_context_manager(self->b_ctx.fd), 0) {
		TH_LOG("Cannot become context manager: %s", strerror(errno));
	}

	self->child_pid = cg_run_nowait(
		self->cg_ctx.dest, child_request_dmabuf_transfer, &self->bfs_ctx);
	ASSERT_GT(self->child_pid, 0) {
		TH_LOG("Error forking: %s", strerror(errno));
	}

	self->tr = binder_wait_for_transaction(self->b_ctx.fd, readbuf, sizeof(readbuf));
	ASSERT_NE(self->tr, NULL) {
		TH_LOG("Error receiving transaction request from child");
	}
	fbo = (struct flat_binder_object *)self->tr->data.ptr.buffer;
	ASSERT_EQ(fbo->hdr.type, BINDER_TYPE_PTR) {
		TH_LOG("Did not receive a buffer object from child");
	}
	bbo = (struct binder_buffer_object *)fbo;
	ASSERT_EQ(bbo->length, 0) {
		TH_LOG("Did not receive an empty buffer object from child");
	}

	TH_LOG("Received transaction from child");
}

FIXTURE_TEARDOWN(fix)
{
	close_binder(&self->b_ctx);
	close(self->dmabuf_fd);
	destroy_cgroups(_metadata, &self->cg_ctx);
	destroy_binderfs(&self->bfs_ctx);
}


void verify_transfer_success(struct _test_data_fix *self, struct __test_metadata *_metadata)
{
	ASSERT_EQ(cg_read_key_long(self->cg_ctx.dest, GPUMEM_FILENAME, "system-heap"), ONE_MiB) {
		TH_LOG("Destination cgroup does not have system-heap charge!");
	}
	ASSERT_EQ(cg_read_key_long(self->cg_ctx.source, GPUMEM_FILENAME, "system-heap"), 0) {
		TH_LOG("Source cgroup still has system-heap charge!");
	}
	TH_LOG("Charge transfer succeeded!");
}

TEST_F(fix, individual_fd)
{
	send_dmabuf_reply_fd(self->b_ctx.fd, self->tr, self->dmabuf_fd);
	verify_transfer_success(self, _metadata);
}

TEST_F(fix, fd_array)
{
	send_dmabuf_reply_fda(self->b_ctx.fd, self->tr, self->dmabuf_fd);
	verify_transfer_success(self, _metadata);
}

TEST_HARNESS_MAIN
