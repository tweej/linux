/* SPDX-License-Identifier: MIT
 * Copyright 2019 Advanced Micro Devices, Inc.
 * Copyright (C) 2022 Google LLC.
 */
#ifndef _CGROUP_GPU_H
#define _CGROUP_GPU_H

#include <linux/cgroup.h>

#define GPUCG_BUCKET_NAME_MAX_LEN 64

struct gpucg;
struct gpucg_bucket;

#ifdef CONFIG_CGROUP_GPU

/**
 * gpucg_get - Get the gpucg that a task belongs to
 *
 * @task: the target task
 *
 * This increases the reference count of the css that the @task belongs to.
 *
 * Return: A pointer to the gpu cgroup the task belongs to.
 */
struct gpucg *gpucg_get(struct task_struct *task);

/**
 * gpucg_put - Put a gpucg reference
 *
 * @gpucg: the target gpucg
 *
 * Put a reference obtained via gpucg_get.
 */
void gpucg_put(struct gpucg *gpucg);

/**
 * gpucg_charge_current - Charge memory to the cgroup of the current task_struct
 *
 * @bucket: The bucket to charge the memory to.
 * @size: The size of memory to charge in bytes.
 *        This size will be rounded up to the nearest page size.
 *
 * Return: A pointer to the current cgroup on success.
 *         If the GPU controller is not enabled then NULL.
 * 	   Otherwise a negative errno code encoded into the pointer.
 */
struct gpucg *gpucg_charge_current(struct gpucg_bucket *bucket, u64 size);

/**
 * gpucg_uncharge - Uncharge memory from the specified gpucg and gpucg_bucket
 *
 * @gpucg: The gpu cgroup to uncharge the memory from.
 * @bucket: The bucket to uncharge the memory from.
 * @size: The size of memory to uncharge in bytes.
 *        This size will be rounded up to the nearest page size.
 */
void gpucg_uncharge(struct gpucg *gpucg, struct gpucg_bucket *bucket, u64 size);


/**
 * gpucg_register_bucket - Registers a bucket for memory accounting using the GPU cgroup controller
 *
 * @name: Pointer to a null-terminated string to denote the name of the bucket.
 * @suffix: If not NULL, pointer to a null-terminated string that will be appended to @name.
 *
 * The bucket name (resulting from the optional appending of suffix to name) should be globally
 * unique, and should not exceed @GPUCG_BUCKET_NAME_MAX_LEN bytes.
 *
 * Return: A pointer to a newly allocated bucket on success, otherwise a negative errno code encoded
 *         into the pointer.
 */
struct gpucg_bucket *gpucg_register_bucket(const char *name, const char *suffix);

#else /* CONFIG_CGROUP_GPU */

static inline struct gpucg *gpucg_get(struct task_struct *task)
{
	return NULL;
}

static inline void gpucg_put(struct gpucg *gpucg) {}

static inline struct gpucg *gpucg_charge_current(struct gpucg_bucket *bucket, u64 size)
{
	return NULL;
}

static inline void gpucg_uncharge(struct gpucg *gpucg,
				  struct gpucg_bucket *bucket,
				  u64 size) {}


static inline struct gpucg_bucket *gpucg_register_bucket(const char *name, const char *suffix)
{
	return NULL;
}
#endif /* CONFIG_CGROUP_GPU */
#endif /* _CGROUP_GPU_H */
