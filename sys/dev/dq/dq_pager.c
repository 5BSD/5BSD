/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: the dq pager (design 10, D12 as made concrete by D102
 * and D105).
 *
 * Every served object has its own VM object of the dq pager type, created
 * at MINT with handle = the dq object, so two objects presenting the same
 * identity never share pages.  Pages exist while mapped, wired (sendfile
 * in flight) or cached under dp_cache = DATA; REVOKE, queue close and
 * object close remove them.  The pager is its own dynamic type and never
 * OBJ_SWAP (with OBJ_SWAP vm_fault zero-fills without asking the pager):
 *
 *   getpages        posts READ for the run and waits as a fault waits
 *                   (DQ_POST_FAULT, B4); a failure is VM_PAGER_ERROR (FAIL
 *                   would zero-fill), a page wholly past the presented size
 *                   VM_PAGER_BAD; a short reply zero-fills the tail.
 *   getpages_async  posts READ_ASYNC (sendfile); the requested pages stay
 *                   busy and iodone runs exactly once on every path.
 *   putpages        posts WRITE_ASYNC through dq_async_post and answers
 *                   VM_PAGER_PEND; the pages stay share-busy with paging
 *                   in progress until the completion (B1-B3).  Nothing
 *                   here waits for the controller (I11).
 *   haspage         from the object's size, which follows the identity.
 *   sync            msync(2) and fsync: vm_object_page_clean (PGO_WRITEBACK)
 *                   and, under MS_SYNC, a wait for the completions (D42).
 *   kinfo           a vnode-looking report from the presented identity.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/dqres.h>
#include <sys/rwlock.h>
#include <sys/taskqueue.h>
#include <sys/user.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

static pgo_alloc_t		dq_pager_alloc;
static pgo_dealloc_t		dq_pager_dealloc;
static pgo_getpages_t		dq_pager_getpages;
static pgo_getpages_async_t	dq_pager_getpages_async;
static pgo_putpages_t		dq_pager_putpages;
static pgo_haspage_t		dq_pager_haspage;
static pgo_writecount_t		dq_pager_update_writecount;
static pgo_writecount_t		dq_pager_release_writecount;
static pgo_sync_t		dq_pager_sync;
static pgo_kinfo_t		dq_pager_kinfo;
static bool	dq_object_errs_in(struct dq_object *o, uint64_t errs0,
		    off_t start, off_t end);

/*
 * Every member is named.  NULL members are deliberate: populate (no bulk
 * pagein), pageunswapped (no swap), getvp (no vnode: MAP_VN_EXEC and the
 * text accounting tolerate NULL), freespace (nothing to free beyond the
 * pages), page_inserted/removed (no per-page pager state), can_alloc_page
 * (always), init (a dynamic type gets none; registered in dq_init).
 */
static struct pagerops dq_pagerops = {
	.pgo_kvme_type =	KVME_TYPE_VNODE,
	.pgo_flags =		PGO_WRITEBACK | PGO_RESIDENT_LOOKUP,
	.pgo_init =		NULL,
	.pgo_alloc =		dq_pager_alloc,
	.pgo_dealloc =		dq_pager_dealloc,
	.pgo_getpages =		dq_pager_getpages,
	.pgo_getpages_async =	dq_pager_getpages_async,
	.pgo_putpages =		dq_pager_putpages,
	.pgo_haspage =		dq_pager_haspage,
	.pgo_populate =		NULL,
	.pgo_pageunswapped =	NULL,
	.pgo_update_writecount = dq_pager_update_writecount,
	.pgo_release_writecount = dq_pager_release_writecount,
	.pgo_set_writeable_dirty = vm_object_set_writeable_dirty_,
	.pgo_mightbedirty =	vm_object_mightbedirty_,
	.pgo_getvp =		NULL,
	.pgo_freespace =	NULL,
	.pgo_page_inserted =	NULL,
	.pgo_page_removed =	NULL,
	.pgo_can_alloc_page =	NULL,
	.pgo_sync =		dq_pager_sync,
	.pgo_kinfo =		dq_pager_kinfo,
};

int dq_pager_type = -1;

int
dq_pager_register(void)
{
	int type;

	type = vm_pager_alloc_dyn_type(&dq_pagerops, -1);
	if (type < 0)
		return (ENOSPC);
	dq_pager_type = type;
	return (0);
}

/*
 * The inverse of dq_pager_register, for a dq_init that fails before any
 * object exists.
 */
void
dq_pager_unregister(void)
{

	KASSERT(dq_pager_type >= 0, ("dq: no pager type to unregister"));
	vm_pager_free_dyn_type(dq_pager_type);
	dq_pager_type = -1;
}

/* The largest page run one event carries. */
static int
dq_pager_maxpages(void)
{

	return (MAX(1, (int)(dq_max_io / PAGE_SIZE)));
}

/*
 * pgo_dealloc runs at vm_object_terminate with the object write-locked.
 * The VM object's reference on the dq object is dropped from dq_taskq: the
 * last release may free the queue, which sleeps (knlist_clear).
 */
static void
dq_pager_rele_task(void *arg, int pending __unused)
{

	dq_object_rele(arg);
}

/*
 * The pager object of a minted object.  It holds a reference on the dq
 * object (released after pgo_dealloc); the dq object holds the creation
 * reference on it until dq_close.
 */
int
dq_object_vm_create(struct dq_object *o)
{
	vm_object_t obj;
	off_t size;

	if (dq_pager_type < 0)
		return (ENXIO);
	size = o->o_ident.di_size;
	obj = vm_object_allocate_dyn(dq_pager_type,
	    OFF_TO_IDX((uint64_t)size + PAGE_MASK), OBJ_COLORED);
	TASK_INIT(&o->o_rele_task, 0, dq_pager_rele_task, o);
	dq_object_hold(o);		/* the VM object's */
	VM_OBJECT_WLOCK(obj);
	obj->handle = o;
	o->o_vmsize = size;
	VM_OBJECT_WUNLOCK(obj);
	o->o_object = obj;
	return (0);
}

/* Objects are created at MINT only; a lookup by handle never allocates. */
static vm_object_t
dq_pager_alloc(void *handle __unused, vm_ooffset_t size __unused,
    vm_prot_t prot __unused, vm_ooffset_t foff __unused,
    struct ucred *cred __unused)
{

	return (NULL);
}

static void
dq_pager_dealloc(vm_object_t obj)
{
	struct dq_object *o;

	VM_OBJECT_ASSERT_WLOCKED(obj);
	o = obj->handle;
	obj->handle = NULL;
	/* Every pager marks its object dead here (vm_object_zdtor asserts it). */
	obj->type = OBJT_DEAD;
	if (o != NULL)
		taskqueue_enqueue(dq_taskq, &o->o_rele_task);
}

static struct dq_object *
dq_pager_object(vm_object_t obj)
{
	struct dq_object *o;

	o = obj->handle;
	if (o == NULL || atomic_load_bool(&o->o_closing) ||
	    atomic_load_bool(&o->o_closed))
		return (NULL);
	return (o);
}

/*
 * The size the pager serves: o_vmsize, which follows the presented size
 * (B10) and which a shrink moves before it fails the page operations past
 * it, so a page-in never races a truncation into a stale page.
 */
static off_t
dq_pager_size(struct dq_object *o)
{
	off_t size;

	DQO_LOCK(o);
	size = o->o_vmsize;
	DQO_UNLOCK(o);
	return (size);
}

/*
 * Copy dlen bytes of data into the run's pages, zero-filling every byte
 * past them; bogus pages (sendfile's already-valid ones) are skipped.
 * The pages are busy; no lock is needed.
 */
static void
dq_pager_fill(vm_page_t *ma, int count, const char *data, size_t dlen)
{
	void *va;
	size_t off, cnt;
	int i;

	for (i = 0; i < count; i++) {
		if (ma[i] == bogus_page)
			continue;
		off = (size_t)i * PAGE_SIZE;
		cnt = dlen > off ? MIN(PAGE_SIZE, dlen - off) : 0;
		va = pmap_quick_enter_page(ma[i]);
		if (cnt != 0)
			memcpy(va, data + off, cnt);
		if (cnt < PAGE_SIZE)
			bzero((char *)va + cnt, PAGE_SIZE - cnt);
		pmap_quick_remove_page(va);
	}
}

void
dq_pager_fill_run(vm_page_t *ma, int count, const char *data, size_t dlen)
{

	dq_pager_fill(ma, count, data, dlen);
}

/*
 * A fault or a DATA-mode read miss.  The object is unlocked, the pages
 * exclusive-busy with paging in progress (vm_pager_assert_in).  No
 * read-ahead or read-behind: the run is what was asked.
 */
static int
dq_pager_getpages(vm_object_t obj, vm_page_t *ma, int count, int *rbehind,
    int *rahead)
{
	struct dq_object *o;
	struct dq_read_body rb;
	struct dq_data *reply;
	off_t off, size;
	size_t len, done, chunk, rlen, maxchunk;
	uint64_t gen;
	int error, filled, i, npg, rerror, tries;

	if (rbehind != NULL)
		*rbehind = 0;
	if (rahead != NULL)
		*rahead = 0;
	o = dq_pager_object(obj);
	if (o == NULL)
		return (VM_PAGER_ERROR);
	off = IDX_TO_OFF(ma[0]->pindex);
	maxchunk = (size_t)dq_pager_maxpages() * PAGE_SIZE;
	for (tries = 0;; tries++) {
		size = dq_pager_size(o);
		if (off >= size)
			return (VM_PAGER_BAD);
		len = MIN((size_t)count * PAGE_SIZE, (size_t)(size - off));
		gen = dq_object_invalgen(o);
		filled = 0;
		for (done = 0; done < len; done += chunk) {
			chunk = MIN(len - done, maxchunk);
			rb.dr_offset = off + done;
			rb.dr_len = chunk;
			rb.dr_pad0 = 0;
			error = dq_event_post_wait(o, DQ_OP_READ, &rb,
			    sizeof(rb), curthread, DQ_POST_FAULT, &reply,
			    &rerror);
			if (error != 0) {
				/* Failed by a shrink past it: SIGBUS. */
				return (off >= dq_pager_size(o) ?
				    VM_PAGER_BAD : VM_PAGER_ERROR);
			}
			if (rerror != 0) {
				dq_reply_free(reply);
				return (VM_PAGER_ERROR);
			}
			/* A post-operation block of a page-in is not used. */
			rlen = reply != NULL ? reply->dd_plen : 0;
			npg = howmany(chunk, PAGE_SIZE);
			dq_pager_fill(ma + filled, npg, reply != NULL ?
			    reply->dd_bytes : NULL, rlen);
			dq_reply_free(reply);
			filled += npg;
			if (rlen < chunk) {
				/*
				 * Short: the end of the file only where the
				 * presented size says so.  A hole inside it is
				 * an error, never cached zeros.
				 */
				if (off + (off_t)(done + rlen) <
				    dq_pager_size(o))
					return (VM_PAGER_ERROR);
				break;
			}
		}
		if (filled < count)
			dq_pager_fill(ma + filled, count - filled, NULL, 0);
		/*
		 * An INVALIDATE while the READ was out may have skipped these
		 * busy pages: what was read may predate the change.  Read
		 * again (a controller invalidating without end gets ERROR).
		 */
		if (dq_object_invalgen(o) == gen)
			break;
		if (tries >= 8)
			return (VM_PAGER_ERROR);
	}
	/*
	 * A shrink that ran while the READ was out zeroed only what was not
	 * busy; the bytes past the size now are zeros here (B10).
	 */
	dq_pager_zero_past(o, ma, count, off);
	for (i = 0; i < count; i++) {
		if (ma[i] != bogus_page)
			vm_page_valid(ma[i]);
	}
	return (VM_PAGER_OK);
}

/* The bytes of a page run past the pager's size are zeros. */
void
dq_pager_zero_past(struct dq_object *o, vm_page_t *ma, int count, off_t off)
{
	off_t pstart, size;
	int i, zbase;

	size = dq_pager_size(o);
	for (i = 0; i < count; i++) {
		if (ma[i] == bogus_page)
			continue;
		pstart = off + (off_t)i * PAGE_SIZE;
		if (pstart + PAGE_SIZE > size) {
			zbase = size > pstart ? (int)(size - pstart) : 0;
			pmap_zero_page_area(ma[i], zbase, PAGE_SIZE - zbase);
		}
	}
}

uint64_t
dq_object_invalgen(struct dq_object *o)
{
	uint64_t gen;

	DQO_LOCK(o);
	gen = o->o_invalgen;
	DQO_UNLOCK(o);
	return (gen);
}

off_t
dq_object_vmsize(struct dq_object *o)
{

	return (dq_pager_size(o));
}

/*
 * sendfile(2): READ_ASYNC, completed by dq_taskq.  iodone runs exactly
 * once whatever happens (sendfile_iowait spins until it does), and the
 * requested pages stay busy for it (N8).  When the async bounds refuse the
 * post, the run is read synchronously instead, as a fault would read it.
 */
static int
dq_pager_getpages_async(vm_object_t obj, vm_page_t *ma, int count,
    int *rbehind, int *rahead, pgo_getpages_iodone_t iodone, void *arg)
{
	struct dq_object *o;
	off_t off, size;
	size_t len;
	int rv;

	if (rbehind != NULL)
		*rbehind = 0;
	if (rahead != NULL)
		*rahead = 0;
	o = dq_pager_object(obj);
	if (o == NULL) {
		iodone(arg, ma, count, EIO);
		return (VM_PAGER_ERROR);
	}
	off = IDX_TO_OFF(ma[0]->pindex);
	size = dq_pager_size(o);
	if (off >= size) {
		iodone(arg, ma, count, EIO);
		return (VM_PAGER_BAD);
	}
	len = MIN((size_t)count * PAGE_SIZE, (size_t)(size - off));
	rv = VM_PAGER_AGAIN;
	if (len <= (size_t)dq_pager_maxpages() * PAGE_SIZE)
		rv = dq_async_post(o, obj, ma, count, off, len, false, iodone,
		    arg);
	if (rv == VM_PAGER_PEND)
		return (VM_PAGER_OK);
	if (rv == VM_PAGER_AGAIN) {
		rv = dq_pager_getpages(obj, ma, count, NULL, NULL);
		iodone(arg, ma, count, rv == VM_PAGER_OK ? 0 : EIO);
		return (rv);
	}
	iodone(arg, ma, count, EIO);
	return (VM_PAGER_ERROR);
}

/*
 * Writeback of dirty pages (vm_pageout_flush: the page daemon, msync,
 * fsync).  The object is write-locked and the pages share-busied with
 * paging in progress.  Each run of at most max_io (and max_inflight_bytes)
 * bytes is one WRITE_ASYNC; PEND keeps its pages busy until the completion.
 * A page wholly past the presented size is BAD (the page daemon cleans it),
 * a closing or revoked object ERROR (the page stays dirty), and the async
 * bounds AGAIN (the page daemon retries later, msync waits for a
 * completion and retries).  Never blocks.
 */
static void
dq_pager_putpages(vm_object_t obj, vm_page_t *ma, int count, int flags __unused,
    int *rtvals)
{
	struct dq_object *o;
	off_t off, size;
	size_t len;
	int chunkpages, i, j, n, rv;

	VM_OBJECT_ASSERT_WLOCKED(obj);
	for (i = 0; i < count; i++)
		rtvals[i] = VM_PAGER_ERROR;
	o = obj->handle;
	if (o == NULL || o->o_closing)
		return;
	size = o->o_vmsize;		/* the VM object lock is held */
	chunkpages = MIN(dq_pager_maxpages(),
	    MAX(1, (int)(dq_max_inflight_bytes / PAGE_SIZE)));
	for (i = 0; i < count; i += n) {
		off = IDX_TO_OFF(ma[i]->pindex);
		if (off >= size) {
			for (j = i; j < count; j++)
				rtvals[j] = VM_PAGER_BAD;
			break;
		}
		/* A run is contiguous and ends at the presented size. */
		n = 1;
		while (i + n < count && n < chunkpages &&
		    ma[i + n]->pindex == ma[i]->pindex + n &&
		    IDX_TO_OFF(ma[i + n]->pindex) < size)
			n++;
		len = MIN((size_t)n * PAGE_SIZE, (size_t)(size - off));
		rv = dq_async_post(o, obj, ma + i, n, off, len, true, NULL,
		    NULL);
		for (j = i; j < i + n; j++)
			rtvals[j] = rv;
		if (rv == VM_PAGER_AGAIN) {
			o->o_again = true;
			for (j = i + n; j < count; j++)
				rtvals[j] = VM_PAGER_AGAIN;
			break;
		}
		if (rv != VM_PAGER_PEND)
			break;		/* ERROR: the rest stay ERROR */
	}
}

/*
 * Residency is the object's: a page index below the object's size (which
 * follows the presented size) exists.  The hint after lets sendfile ask
 * for as many pages as one event carries.
 */
static boolean_t
dq_pager_haspage(vm_object_t obj, vm_pindex_t pindex, int *before, int *after)
{

	VM_OBJECT_ASSERT_LOCKED(obj);
	if (pindex >= obj->size)
		return (FALSE);
	if (before != NULL)
		*before = 0;
	if (after != NULL)
		*after = (int)MIN(obj->size - pindex - 1,
		    (vm_pindex_t)dq_pager_maxpages() - 1);
	return (TRUE);
}

/*
 * Shared writable mappings, in bytes (D103).  A served file has no text
 * accounting to keep (dp_exec is DENY), so this is bookkeeping a debugger
 * and the tests can read.
 */
static void
dq_pager_update_writecount(vm_object_t obj, vm_offset_t start, vm_offset_t end)
{
	struct dq_object *o;

	o = obj->handle;
	if (o != NULL)
		atomic_add_long(&o->o_writemappings, end - start);
}

static void
dq_pager_release_writecount(vm_object_t obj, vm_offset_t start,
    vm_offset_t end)
{
	struct dq_object *o;

	o = obj->handle;
	if (o != NULL)
		atomic_subtract_long(&o->o_writemappings, end - start);
}

/*
 * Write back [offset, offset + size) (N1: vm_object_page_clean, which
 * PGO_WRITEBACK lets flush this pager's pages), retrying after one
 * completion whenever the async bounds answered AGAIN, never spinning and
 * never past the page deadline; under syncio, wait until every WRITE_ASYNC
 * of the object has completed (D42: msync(MS_SYNC) and fsync wait for the
 * completion, not the controller's reply); invalidate drops the clean pages
 * as vnode_pager_sync does (OBJPR_CLEANONLY: a dirty page is not lost).
 * Entered and left with the object write-locked; the lock is dropped to
 * wait.  FALSE if any page was not written.
 */
boolean_t
dq_pager_flush(struct dq_object *o, vm_object_t obj, vm_ooffset_t offset,
    vm_size_t size, boolean_t syncio, boolean_t invalidate)
{
	sbintime_t deadline, start;
	uint64_t errs;
	boolean_t res;
	int flags;

	VM_OBJECT_ASSERT_WLOCKED(obj);
	res = TRUE;
	start = sbinuptime();
	deadline = dq_page_deadline(o);
	DQO_LOCK(o);
	errs = o->o_async_errs;
	DQO_UNLOCK(o);
	flags = (syncio || invalidate) ? OBJPC_SYNC : 0;
	flags |= invalidate ? OBJPC_INVAL : 0;
	for (;;) {
		if (o->o_closing) {
			res = FALSE;
			break;
		}
		o->o_again = false;
		if (!vm_object_page_clean(obj, offset, offset + size, flags))
			res = FALSE;
		if (!o->o_again)
			break;
		VM_OBJECT_WUNLOCK(obj);
		if (!dq_async_wait(o, deadline, false)) {
			VM_OBJECT_WLOCK(obj);
			res = FALSE;
			break;
		}
		VM_OBJECT_WLOCK(obj);
	}
	if (syncio) {
		VM_OBJECT_WUNLOCK(obj);
		/*
		 * Each pending WRITE_ASYNC carries its own queue-enforced
		 * deadline, so this wait ends; twice the page deadline is the
		 * backstop against a writer that keeps posting.
		 */
		if (!dq_async_wait(o, deadline + (deadline - start), true))
			res = FALSE;
		/*
		 * Only a failed write-back inside this flush's range is this
		 * caller's error, not another range's (the ring keeps the
		 * last DQ_ERRRING; more than that since the start is counted
		 * as a failure here).
		 */
		if (dq_object_errs_in(o, errs, offset, size == 0 ? OFF_MAX :
		    offset + size))
			res = FALSE;
		VM_OBJECT_WLOCK(obj);
	}
	if (invalidate)
		vm_object_page_remove(obj, OFF_TO_IDX(offset),
		    OFF_TO_IDX(offset + size + PAGE_MASK), OBJPR_CLEANONLY);
	return (res);
}

/*
 * Did a write-back failure since errs0 touch [start, end)?
 */
static bool
dq_object_errs_in(struct dq_object *o, uint64_t errs0, off_t start, off_t end)
{
	uint64_t g;
	bool hit;
	int i;

	hit = false;
	DQO_LOCK(o);
	if (o->o_async_errs - errs0 > DQ_ERRRING)
		hit = true;
	for (i = 0; !hit && i < DQ_ERRRING; i++) {
		g = o->o_errring[i].er_gen;
		if (g > errs0 && g <= o->o_async_errs &&
		    o->o_errring[i].er_start < end &&
		    o->o_errring[i].er_end > start)
			hit = true;
	}
	DQO_UNLOCK(o);
	return (hit);
}

static boolean_t
dq_pager_sync(vm_object_t obj, vm_ooffset_t offset, vm_size_t size,
    boolean_t syncio, boolean_t invalidate)
{
	struct dq_object *o;

	VM_OBJECT_ASSERT_WLOCKED(obj);
	o = obj->handle;
	if (o == NULL)
		return (TRUE);
	return (dq_pager_flush(o, obj, offset, size, syncio, invalidate));
}

/*
 * What procstat -v, kinfo_getvmmap(3) and linprocfs show for a mapping: the
 * presented identity, as a regular file's vnode would report itself, its
 * path presented against the reader td as fill_kinfo presents the
 * descriptor's (D174): relative to a served root of the same queue, the
 * raw di_path for any other reader, empty when not underneath.  The object
 * is referenced and unlocked (vm_object_kinfo), so the presentation may
 * sleep; handle stays until termination.
 */
static void
dq_pager_kinfo(vm_object_t obj, struct vm_object_kinfo *ki, struct thread *td)
{
	struct dq_object *o;
	struct dq_ident_file *di;

	o = obj->handle;
	if (o == NULL)
		return;
	di = malloc(sizeof(*di), M_TEMP, M_WAITOK);
	DQO_LOCK(o);
	*di = o->o_ident;
	DQO_UNLOCK(o);
	ki->vk_freepath = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	if (dqres_present_viewer(td, o->o_queue->q_gid, di->di_path,
	    di->di_pathlen, ki->vk_freepath, MAXPATHLEN) != 0)
		ki->vk_freepath[0] = '\0';
	ki->vk_path = ki->vk_freepath;
	ki->vk_vn_type = KF_VTYPE_VREG;
	ki->vk_fileid = di->di_ino;
	ki->vk_fsid = di->di_dev;
	ki->vk_mode = di->di_mode;
	ki->vk_size = di->di_size;
	ki->vk_rdev = di->di_rdev;
	ki->vk_attr_valid = true;
	free(di, M_TEMP);
}

/*
 * After the controller accepted a WRITE (D103), its bytes replace those of
 * the resident, fully valid pages they cover, so a mapping and a cached
 * read see what write(2) wrote, as on a vnode.  The dirty state is left as
 * it is: a page dirtied through a mapping still owes its writeback.  A page
 * share-busied by a pending WRITE_ASYNC is waited for (vm_page_grab sleeps
 * with the object lock dropped; the async deadline bounds it).  Called with
 * the descriptor held, so the VM object is the dq object's.
 */
void
dq_pager_write_resident(struct dq_object *o, off_t offset, const char *data,
    size_t len)
{
	vm_object_t obj;
	vm_page_t m;
	void *va;
	off_t off, end;
	size_t n, pgoff;

	obj = o->o_object;
	if (obj == NULL || len == 0)
		return;
	end = offset + (off_t)len;
	VM_OBJECT_WLOCK(obj);
	if (obj->resident_page_count == 0) {
		VM_OBJECT_WUNLOCK(obj);
		return;
	}
	for (off = offset; off < end; off += n, data += n) {
		pgoff = off & PAGE_MASK;
		n = MIN(PAGE_SIZE - pgoff, (size_t)(end - off));
		m = vm_page_grab(obj, OFF_TO_IDX(off), VM_ALLOC_NOCREAT);
		if (m == NULL)
			continue;
		if (vm_page_all_valid(m)) {
			va = pmap_quick_enter_page(m);
			memcpy((char *)va + pgoff, data, n);
			pmap_quick_remove_page(va);
		}
		vm_page_xunbusy(m);
	}
	VM_OBJECT_WUNLOCK(obj);
}
