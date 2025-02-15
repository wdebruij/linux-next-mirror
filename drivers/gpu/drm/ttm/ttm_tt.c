/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/**************************************************************************
 *
 * Copyright (c) 2006-2009 VMware, Inc., Palo Alto, CA., USA
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/
/*
 * Authors: Thomas Hellstrom <thellstrom-at-vmware-dot-com>
 */

#define pr_fmt(fmt) "[TTM] " fmt

#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/shmem_fs.h>
#include <linux/file.h>
#include <drm/drm_cache.h>
#include <drm/ttm/ttm_bo_driver.h>

/*
 * Allocates a ttm structure for the given BO.
 */
int ttm_tt_create(struct ttm_buffer_object *bo, bool zero_alloc)
{
	struct ttm_bo_device *bdev = bo->bdev;
	uint32_t page_flags = 0;

	dma_resv_assert_held(bo->base.resv);

	if (bo->ttm)
		return 0;

	switch (bo->type) {
	case ttm_bo_type_device:
		if (zero_alloc)
			page_flags |= TTM_PAGE_FLAG_ZERO_ALLOC;
		break;
	case ttm_bo_type_kernel:
		break;
	case ttm_bo_type_sg:
		page_flags |= TTM_PAGE_FLAG_SG;
		break;
	default:
		pr_err("Illegal buffer object type\n");
		return -EINVAL;
	}

	bo->ttm = bdev->driver->ttm_tt_create(bo, page_flags);
	if (unlikely(bo->ttm == NULL))
		return -ENOMEM;

	return 0;
}

/*
 * Allocates storage for pointers to the pages that back the ttm.
 */
static int ttm_tt_alloc_page_directory(struct ttm_tt *ttm)
{
	ttm->pages = kvmalloc_array(ttm->num_pages, sizeof(void*),
			GFP_KERNEL | __GFP_ZERO);
	if (!ttm->pages)
		return -ENOMEM;
	return 0;
}

static int ttm_dma_tt_alloc_page_directory(struct ttm_tt *ttm)
{
	ttm->pages = kvmalloc_array(ttm->num_pages,
				    sizeof(*ttm->pages) +
				    sizeof(*ttm->dma_address),
				    GFP_KERNEL | __GFP_ZERO);
	if (!ttm->pages)
		return -ENOMEM;

	ttm->dma_address = (void *)(ttm->pages + ttm->num_pages);
	return 0;
}

static int ttm_sg_tt_alloc_page_directory(struct ttm_tt *ttm)
{
	ttm->dma_address = kvmalloc_array(ttm->num_pages,
					  sizeof(*ttm->dma_address),
					  GFP_KERNEL | __GFP_ZERO);
	if (!ttm->dma_address)
		return -ENOMEM;
	return 0;
}

void ttm_tt_destroy_common(struct ttm_bo_device *bdev, struct ttm_tt *ttm)
{
	ttm_tt_unpopulate(bdev, ttm);

	if (ttm->swap_storage)
		fput(ttm->swap_storage);

	ttm->swap_storage = NULL;
}
EXPORT_SYMBOL(ttm_tt_destroy_common);

void ttm_tt_destroy(struct ttm_bo_device *bdev, struct ttm_tt *ttm)
{
	bdev->driver->ttm_tt_destroy(bdev, ttm);
}

static void ttm_tt_init_fields(struct ttm_tt *ttm,
			       struct ttm_buffer_object *bo,
			       uint32_t page_flags,
			       enum ttm_caching caching)
{
	ttm->num_pages = bo->num_pages;
	ttm->caching = ttm_cached;
	ttm->page_flags = page_flags;
	ttm->dma_address = NULL;
	ttm->swap_storage = NULL;
	ttm->sg = bo->sg;
	ttm->caching = caching;
}

int ttm_tt_init(struct ttm_tt *ttm, struct ttm_buffer_object *bo,
		uint32_t page_flags, enum ttm_caching caching)
{
	ttm_tt_init_fields(ttm, bo, page_flags, caching);

	if (ttm_tt_alloc_page_directory(ttm)) {
		pr_err("Failed allocating page table\n");
		return -ENOMEM;
	}
	return 0;
}
EXPORT_SYMBOL(ttm_tt_init);

void ttm_tt_fini(struct ttm_tt *ttm)
{
	if (ttm->pages)
		kvfree(ttm->pages);
	else
		kvfree(ttm->dma_address);
	ttm->pages = NULL;
	ttm->dma_address = NULL;
}
EXPORT_SYMBOL(ttm_tt_fini);

int ttm_sg_tt_init(struct ttm_tt *ttm, struct ttm_buffer_object *bo,
		   uint32_t page_flags, enum ttm_caching caching)
{
	int ret;

	ttm_tt_init_fields(ttm, bo, page_flags, caching);

	if (page_flags & TTM_PAGE_FLAG_SG)
		ret = ttm_sg_tt_alloc_page_directory(ttm);
	else
		ret = ttm_dma_tt_alloc_page_directory(ttm);
	if (ret) {
		pr_err("Failed allocating page table\n");
		return -ENOMEM;
	}
	return 0;
}
EXPORT_SYMBOL(ttm_sg_tt_init);

int ttm_tt_swapin(struct ttm_tt *ttm)
{
	struct address_space *swap_space;
	struct file *swap_storage;
	struct page *from_page;
	struct page *to_page;
	gfp_t gfp_mask;
	int i, ret;

	swap_storage = ttm->swap_storage;
	BUG_ON(swap_storage == NULL);

	swap_space = swap_storage->f_mapping;
	gfp_mask = mapping_gfp_mask(swap_space);

	for (i = 0; i < ttm->num_pages; ++i) {
		from_page = shmem_read_mapping_page_gfp(swap_space, i,
							gfp_mask);
		if (IS_ERR(from_page)) {
			ret = PTR_ERR(from_page);
			goto out_err;
		}
		to_page = ttm->pages[i];
		if (unlikely(to_page == NULL)) {
			ret = -ENOMEM;
			goto out_err;
		}

		copy_highpage(to_page, from_page);
		put_page(from_page);
	}

	fput(swap_storage);
	ttm->swap_storage = NULL;
	ttm->page_flags &= ~TTM_PAGE_FLAG_SWAPPED;

	return 0;

out_err:
	return ret;
}

int ttm_tt_swapout(struct ttm_bo_device *bdev, struct ttm_tt *ttm)
{
	struct address_space *swap_space;
	struct file *swap_storage;
	struct page *from_page;
	struct page *to_page;
	gfp_t gfp_mask;
	int i, ret;

	swap_storage = shmem_file_setup("ttm swap",
					ttm->num_pages << PAGE_SHIFT,
					0);
	if (IS_ERR(swap_storage)) {
		pr_err("Failed allocating swap storage\n");
		return PTR_ERR(swap_storage);
	}

	swap_space = swap_storage->f_mapping;
	gfp_mask = mapping_gfp_mask(swap_space);

	for (i = 0; i < ttm->num_pages; ++i) {
		from_page = ttm->pages[i];
		if (unlikely(from_page == NULL))
			continue;

		to_page = shmem_read_mapping_page_gfp(swap_space, i, gfp_mask);
		if (IS_ERR(to_page)) {
			ret = PTR_ERR(to_page);
			goto out_err;
		}
		copy_highpage(to_page, from_page);
		set_page_dirty(to_page);
		mark_page_accessed(to_page);
		put_page(to_page);
	}

	ttm_tt_unpopulate(bdev, ttm);
	ttm->swap_storage = swap_storage;
	ttm->page_flags |= TTM_PAGE_FLAG_SWAPPED;

	return 0;

out_err:
	fput(swap_storage);

	return ret;
}

static void ttm_tt_add_mapping(struct ttm_bo_device *bdev, struct ttm_tt *ttm)
{
	pgoff_t i;

	if (ttm->page_flags & TTM_PAGE_FLAG_SG)
		return;

	for (i = 0; i < ttm->num_pages; ++i)
		ttm->pages[i]->mapping = bdev->dev_mapping;
}

int ttm_tt_populate(struct ttm_bo_device *bdev,
		    struct ttm_tt *ttm, struct ttm_operation_ctx *ctx)
{
	int ret;

	if (!ttm)
		return -EINVAL;

	if (ttm_tt_is_populated(ttm))
		return 0;

	if (bdev->driver->ttm_tt_populate)
		ret = bdev->driver->ttm_tt_populate(bdev, ttm, ctx);
	else
		ret = ttm_pool_alloc(&bdev->pool, ttm, ctx);
	if (ret)
		return ret;

	ttm_tt_add_mapping(bdev, ttm);
	ttm->page_flags |= TTM_PAGE_FLAG_PRIV_POPULATED;
	if (unlikely(ttm->page_flags & TTM_PAGE_FLAG_SWAPPED)) {
		ret = ttm_tt_swapin(ttm);
		if (unlikely(ret != 0)) {
			ttm_tt_unpopulate(bdev, ttm);
			return ret;
		}
	}

	return 0;
}
EXPORT_SYMBOL(ttm_tt_populate);

static void ttm_tt_clear_mapping(struct ttm_tt *ttm)
{
	pgoff_t i;
	struct page **page = ttm->pages;

	if (ttm->page_flags & TTM_PAGE_FLAG_SG)
		return;

	for (i = 0; i < ttm->num_pages; ++i) {
		(*page)->mapping = NULL;
		(*page++)->index = 0;
	}
}

void ttm_tt_unpopulate(struct ttm_bo_device *bdev,
		       struct ttm_tt *ttm)
{
	if (!ttm_tt_is_populated(ttm))
		return;

	ttm_tt_clear_mapping(ttm);
	if (bdev->driver->ttm_tt_unpopulate)
		bdev->driver->ttm_tt_unpopulate(bdev, ttm);
	else
		ttm_pool_free(&bdev->pool, ttm);
	ttm->page_flags &= ~TTM_PAGE_FLAG_PRIV_POPULATED;
}
