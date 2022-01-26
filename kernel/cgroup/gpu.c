// SPDX-License-Identifier: MIT
// Copyright 2019 Advanced Micro Devices, Inc.
// Copyright (C) 2022 Google LLC.

#include <linux/cgroup.h>
#include <linux/cgroup_gpu.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/page_counter.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct gpucg *root_gpucg __read_mostly;

/*
 * Protects list of resource pools maintained on per cgroup basis and list
 * of buckets registered for memory accounting using the GPU cgroup controller.
 */
static DEFINE_MUTEX(gpucg_mutex);
static LIST_HEAD(gpucg_buckets);

/* The GPU cgroup controller data structure */
struct gpucg {
	struct cgroup_subsys_state css;

	/* list of all resource pools that belong to this cgroup */
	struct list_head rpools;
};

/* A named entity representing bucket of tracked memory. */
struct gpucg_bucket {
	/* list of various resource pools in various cgroups that the bucket is part of */
	struct list_head rpools;

	/* list of all buckets registered for GPU cgroup accounting */
	struct list_head bucket_node;

	/* string to be used as identifier for accounting and limit setting */
	const char *name;
};

struct gpucg_resource_pool {
	/* The bucket whose resource usage is tracked by this resource pool */
	struct gpucg_bucket *bucket;

	/* list of all resource pools for the cgroup */
	struct list_head cg_node;

	/* list maintained by the gpucg_bucket to keep track of its resource pools */
	struct list_head bucket_node;

	/* tracks memory usage of the resource pool */
	struct page_counter total;
};

static void free_cg_rpool_locked(struct gpucg_resource_pool *rpool)
{
	lockdep_assert_held(&gpucg_mutex);

	list_del(&rpool->cg_node);
	list_del(&rpool->bucket_node);
	kfree(rpool);
}

/**
 * css_to_gpucg - Get the corresponding gpucg ref from a cgroup_subsys_state
 *
 * @css: the target cgroup_subsys_state
 *
 * Returns: A pointer to the gpu cgroup that contains the @css.
 */
static struct gpucg *css_to_gpucg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct gpucg, css) : NULL;
}

static void gpucg_css_free(struct cgroup_subsys_state *css)
{
	struct gpucg_resource_pool *rpool, *tmp;
	struct gpucg *gpucg = css_to_gpucg(css);

	// delete all resource pools
	mutex_lock(&gpucg_mutex);
	list_for_each_entry_safe(rpool, tmp, &gpucg->rpools, cg_node)
		free_cg_rpool_locked(rpool);
	mutex_unlock(&gpucg_mutex);

	kfree(gpucg);
}

static struct cgroup_subsys_state *
gpucg_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct gpucg *gpucg, *parent;

	gpucg = kzalloc(sizeof(struct gpucg), GFP_KERNEL);
	if (!gpucg)
		return ERR_PTR(-ENOMEM);

	parent = css_to_gpucg(parent_css);
	if (!parent)
		root_gpucg = gpucg;

	INIT_LIST_HEAD(&gpucg->rpools);

	return &gpucg->css;
}

static struct gpucg_resource_pool *cg_rpool_find_locked(
	struct gpucg *cg,
	struct gpucg_bucket *bucket)
{
	struct gpucg_resource_pool *rpool;

	lockdep_assert_held(&gpucg_mutex);

	list_for_each_entry(rpool, &cg->rpools, cg_node)
		if (rpool->bucket == bucket)
			return rpool;

	return NULL;
}

static struct gpucg_resource_pool *cg_rpool_init(struct gpucg *cg,
						 struct gpucg_bucket *bucket)
{
	struct gpucg_resource_pool *rpool = kzalloc(sizeof(*rpool),
							GFP_KERNEL);
	if (!rpool)
		return ERR_PTR(-ENOMEM);

	rpool->bucket = bucket;

	page_counter_init(&rpool->total, NULL);
	INIT_LIST_HEAD(&rpool->cg_node);
	INIT_LIST_HEAD(&rpool->bucket_node);
	list_add_tail(&rpool->cg_node, &cg->rpools);
	list_add_tail(&rpool->bucket_node, &bucket->rpools);

	return rpool;
}

/**
 * gpucg_parent - Find the parent of a gpu cgroup
 *
 * @cg: the target gpucg
 *
 * This does not increase the reference count of the parent cgroup.
 *
 * Return: A pointer to the parent gpu cgroup of @cg
 */
static struct gpucg *gpucg_parent(struct gpucg *cg)
{
	return css_to_gpucg(cg->css.parent);
}

/**
 * get_cg_rpool_locked - find the resource pool for the specified bucket and
 * specified cgroup. If the resource pool does not exist for the cg, it is
 * created in a hierarchical manner in the cgroup and its ancestor cgroups who
 * do not already have a resource pool entry for the bucket.
 *
 * @cg: The cgroup to find the resource pool for.
 * @bucket: The bucket associated with the returned resource pool.
 *
 * Return: return resource pool entry corresponding to the specified bucket in
 * the specified cgroup (hierarchically creating them if not existing already).
 *
 */
static struct gpucg_resource_pool *
cg_rpool_get_locked(struct gpucg *cg, struct gpucg_bucket *bucket)
{
	struct gpucg *parent_cg, *p, *stop_cg;
	struct gpucg_resource_pool *rpool, *tmp_rpool;
	struct gpucg_resource_pool *parent_rpool = NULL, *leaf_rpool = NULL;

	rpool = cg_rpool_find_locked(cg, bucket);
	if (rpool)
		return rpool;

	stop_cg = cg;
	do {
		rpool = cg_rpool_init(stop_cg, bucket);
		if (IS_ERR(rpool))
			goto err;

		if (!leaf_rpool)
			leaf_rpool = rpool;

		stop_cg = gpucg_parent(stop_cg);
		if (!stop_cg)
			break;

		rpool = cg_rpool_find_locked(stop_cg, bucket);
	} while (!rpool);

	/*
	 * Re-initialize page counters of all rpools created in this invocation
	 * to enable hierarchical charging.
	 * stop_cg is the first ancestor cg who already had a resource pool for
	 * the bucket. It can also be NULL if no ancestors had a pre-existing
	 * resource pool for the bucket before this invocation.
	 */
	rpool = leaf_rpool;
	for (p = cg; p != stop_cg; p = parent_cg) {
		parent_cg = gpucg_parent(p);
		if (!parent_cg)
			break;
		parent_rpool = cg_rpool_find_locked(parent_cg, bucket);
		page_counter_init(&rpool->total, &parent_rpool->total);

		rpool = parent_rpool;
	}

	return leaf_rpool;
err:
	for (p = cg; p != stop_cg; p = gpucg_parent(p)) {
		tmp_rpool = cg_rpool_find_locked(p, bucket);
		free_cg_rpool_locked(tmp_rpool);
	}
	return rpool;
}

struct gpucg *gpucg_get(struct task_struct *task)
{
	if (!cgroup_subsys_enabled(gpu_cgrp_subsys))
		return NULL;
	return css_to_gpucg(task_get_css(task, gpu_cgrp_id));
}

void gpucg_put(struct gpucg *gpucg)
{
	if (gpucg)
		css_put(&gpucg->css);
}

/**
 * gpucg_charge - Charge memory to the specified gpucg and gpucg_bucket
 *
 * @gpucg: The gpu cgroup to charge the memory to.
 * @bucket: The bucket to charge the memory to.
 * @size: The size of memory to charge in bytes.
 *        This size will be rounded up to the nearest page size.
 *
 * The caller must hold a reference to @gpucg obtained through gpucg_get(). The size of the memory
 * is rounded up to be a multiple of the page size.
 *
 * Return: 0 on success, or a negative errno code otherwise.
 */
static int gpucg_charge(struct gpucg *gpucg, struct gpucg_bucket *bucket, u64 size)
{
	struct page_counter *counter;
	u64 nr_pages;
	struct gpucg_resource_pool *rp;
	int ret = 0;

	nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;

	mutex_lock(&gpucg_mutex);
	rp = cg_rpool_get_locked(gpucg, bucket);
	/*
	 * Continue to hold gpucg_mutex because we use it to block charges while transfers are in
	 * progress to avoid potentially exceeding a limit.
	 */
	if (IS_ERR(rp)) {
		mutex_unlock(&gpucg_mutex);
		return PTR_ERR(rp);
	}

	if (page_counter_try_charge(&rp->total, nr_pages, &counter))
		css_get(&gpucg->css);
	else
		ret = -ENOMEM;
	mutex_unlock(&gpucg_mutex);

	return ret;
}

struct gpucg *gpucg_charge_current(struct gpucg_bucket *bucket, u64 size)
{
	int ret;
	struct gpucg *current_gpucg = gpucg_get(current);

	if (!current_gpucg)
		return NULL;

	ret = gpucg_charge(current_gpucg, bucket, size);
	gpucg_put(current_gpucg);
	if (ret)
		return ERR_PTR(ret);

	return current_gpucg;
}
EXPORT_SYMBOL_GPL(gpucg_charge_current);

static void remove_empty_bucket_locked(struct gpucg *cg,
				struct gpucg_bucket *bucket,
				struct gpucg_resource_pool *rp)
{
	struct gpucg *parent_cg;
	struct gpucg_resource_pool *parent_rp;

	lockdep_assert_held(&gpucg_mutex);

	while (rp && page_counter_read(&rp->total) == 0) {
		parent_cg = gpucg_parent(cg);
		parent_rp = parent_cg ? cg_rpool_find_locked(parent_cg, bucket) : NULL;

		free_cg_rpool_locked(rp);

		rp = parent_rp;
		cg = parent_cg;
	}
}

void gpucg_uncharge(struct gpucg *gpucg, struct gpucg_bucket *bucket, u64 size)
{
	u64 nr_pages;
	struct gpucg_resource_pool *rp;

	if (!gpucg || !bucket || !size)
		return;

	mutex_lock(&gpucg_mutex);
	rp = cg_rpool_find_locked(gpucg, bucket);
	if (WARN_RATELIMIT(!rp,
			   "Resource pool not found, incorrect charge/uncharge ordering?\n"))
		goto end;

	nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	page_counter_uncharge(&rp->total, nr_pages);
	css_put(&gpucg->css);

	remove_empty_bucket_locked(gpucg, bucket, rp);
end:
	mutex_unlock(&gpucg_mutex);
}
EXPORT_SYMBOL_GPL(gpucg_uncharge);

struct gpucg_bucket *gpucg_register_bucket(const char *name, const char *suffix)
{
	struct gpucg_bucket *bucket, *b;
	size_t len;

	if (!name)
		return ERR_PTR(-EINVAL);

	len = strlen(name) + (suffix ? strlen(suffix) : 0);
	if (len >= GPUCG_BUCKET_NAME_MAX_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	bucket = kzalloc(sizeof(struct gpucg_bucket), GFP_KERNEL);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&bucket->bucket_node);
	INIT_LIST_HEAD(&bucket->rpools);
	if (!suffix)
		bucket->name = kstrdup_const(name, GFP_KERNEL);
	else
		bucket->name = kasprintf(GFP_KERNEL, "%s%s", name, suffix);

	mutex_lock(&gpucg_mutex);
	list_for_each_entry(b, &gpucg_buckets, bucket_node) {
		if (strncmp(b->name, bucket->name, GPUCG_BUCKET_NAME_MAX_LEN) == 0) {
			mutex_unlock(&gpucg_mutex);
			kfree_const(bucket->name);
			kfree(bucket);
			return ERR_PTR(-EEXIST);
		}
	}
	list_add_tail(&bucket->bucket_node, &gpucg_buckets);
	mutex_unlock(&gpucg_mutex);

	return bucket;
}
EXPORT_SYMBOL_GPL(gpucg_register_bucket);

static int gpucg_resource_show(struct seq_file *sf, void *v)
{
	struct gpucg_resource_pool *rpool;
	struct gpucg *cg = css_to_gpucg(seq_css(sf));

	mutex_lock(&gpucg_mutex);
	list_for_each_entry(rpool, &cg->rpools, cg_node) {
		seq_printf(sf, "%s %lu\n", rpool->bucket->name,
			   page_counter_read(&rpool->total) * PAGE_SIZE);
	}
	mutex_unlock(&gpucg_mutex);

	return 0;
}

struct cftype files[] = {
	{
		.name = "memory.current",
		.seq_show = gpucg_resource_show,
	},
	{ }     /* terminate */
};

struct cgroup_subsys gpu_cgrp_subsys = {
	.css_alloc      = gpucg_css_alloc,
	.css_free       = gpucg_css_free,
	.early_init     = false,
	.legacy_cftypes = files,
	.dfl_cftypes    = files,
};
