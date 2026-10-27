/* SPDX-License-Identifier: BSD-2-Clause */
/* Explicitly constructed, read-only authenticated-block GEOM provider. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <geom/geom.h>
#include <geom/verity/g_verity_io.h>
#include <geom/verity/g_verity_provider.h>

static MALLOC_DEFINE(M_VERITY, "gverity", "GEOM verifier workers");

struct verity_softc;
struct verity_worker {
	struct verity_softc *sc;
	struct g_verity_cache cache;
	void *allocation, *data, *hashes, *window;
};
struct verity_softc {
	struct g_geom *geom;
	struct g_provider *provider;
	struct g_verity_backing backing;
	struct mtx lock;
	struct bio_queue_head queue;
	struct verity_worker *workers;
	size_t window_size;
	unsigned allocated, running; /* running includes the constructor reference. */
	bool stopping, drained;
};
static struct g_class g_verity_class;

static void
verity_free(struct verity_softc *sc)
{
	unsigned i;

	g_topology_assert();
	KASSERT(sc->running == 0 && sc->drained, ("verity workers still live"));
	for (i = 0; i < sc->allocated; i++)
		free(sc->workers[i].allocation, M_VERITY);
	free(sc->workers, M_VERITY);
	mtx_destroy(&sc->lock);
	sc->geom->softc = NULL;
	free(sc, M_VERITY);
}

static void
verity_drained(void *arg, int flags)
{
	struct verity_softc *sc = arg;
	struct g_geom *gp = sc->geom;

	g_topology_assert();
	KASSERT(flags != EV_CANCEL, ("verity drain event cancelled"));
	sc->drained = true;
	if (sc->provider == NULL)
		verity_free(sc);
	/* No backing request can remain after the last worker posts this event. */
	g_wither_geom_close(gp, ENXIO);
}

static void
verity_providergone(struct g_provider *pp)
{
	struct verity_softc *sc = pp->geom->softc;

	g_topology_assert();
	sc->provider = NULL;
	if (sc->drained)
		verity_free(sc);
}

static void
verity_worker(void *arg)
{
	struct verity_worker *worker = arg;
	struct verity_softc *sc = worker->sc;
	struct g_verity_read_window window;
	struct bio *bp;
	bool stop, last;
	int error;

	for (;;) {
		mtx_lock(&sc->lock);
		while ((bp = bioq_takefirst(&sc->queue)) == NULL && !sc->stopping)
			msleep(sc, &sc->lock, PRIBIO, "verityq", 0);
		stop = sc->stopping;
		if (bp == NULL) {
			last = --sc->running == 0;
			mtx_unlock(&sc->lock);
			if (last)
				g_post_event(verity_drained, sc, M_WAITOK, NULL);
			kproc_exit(0);
		}
		mtx_unlock(&sc->lock);
		error = ENXIO;
		if (!stop) {
			error = g_verity_window_init(&window, &sc->backing,
			    bp->bio_offset, bp->bio_length, worker->window,
			    sc->window_size);
			if (error == 0)
				error = g_verity_cached_read_range(&worker->cache,
				    bp->bio_offset, bp->bio_length,
				    g_verity_window_read, &window, worker->data,
				    worker->hashes, bp->bio_data);
		}
		if (error != 0)
			memset(bp->bio_data, 0, bp->bio_length);
		bp->bio_completed = error == 0 ? bp->bio_length : 0;
		g_io_deliver(bp, error);
	}
}

static void
verity_stop(struct verity_softc *sc)
{
	bool last;

	g_topology_assert();
	mtx_lock(&sc->lock);
	if (sc->stopping) {
		mtx_unlock(&sc->lock);
		return;
	}
	sc->stopping = true;
	last = sc->running == 0;
	wakeup(sc);
	mtx_unlock(&sc->lock);
	if (sc->provider != NULL)
		g_wither_provider(sc->provider, ENXIO);
	/* Construction retains a reference even before workers exist. */
	if (last)
		g_post_event(verity_drained, sc, M_WAITOK, NULL);
}

/* Release only after construction no longer uses sc, including error paths. */
static void
verity_constructor_done(struct verity_softc *sc)
{
	bool last;

	g_topology_assert();
	mtx_lock(&sc->lock);
	KASSERT(sc->running > 0, ("missing verity constructor reference"));
	last = --sc->running == 0;
	KASSERT(!last || sc->stopping, ("verity constructor left no workers"));
	mtx_unlock(&sc->lock);
	if (last)
		g_post_event(verity_drained, sc, M_WAITOK, NULL);
}

static void
verity_orphan(struct g_consumer *cp)
{
	verity_stop(cp->geom->softc);
}

static void
verity_resize(struct g_consumer *cp)
{
	/* A bound image has fixed geometry; do not silently rebind it. */
	verity_stop(cp->geom->softc);
}

static int
verity_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct verity_softc *sc = pp->geom->softc;

	g_topology_assert();
	if (dw > 0)
		return (EROFS);
	if (sc->stopping && (dr > 0 || de > 0))
		return (ENXIO);
	return (0);
}

static void
verity_start(struct bio *bp)
{
	struct verity_softc *sc = bp->bio_to->geom->softc;
	int error;

	switch (bp->bio_cmd) {
	case BIO_WRITE:
	case BIO_DELETE:
		error = EROFS;
		break;
	case BIO_READ:
		if ((bp->bio_flags & (BIO_UNMAPPED | BIO_VLIST)) != 0 ||
		    bp->bio_data == NULL || bp->bio_offset < 0 ||
		    bp->bio_length < 0 || (uint64_t)bp->bio_length > SIZE_MAX ||
		    (uint64_t)bp->bio_offset > sc->backing.data_bytes ||
		    (uint64_t)bp->bio_length > sc->backing.data_bytes -
		    (uint64_t)bp->bio_offset) {
			error = EINVAL;
			break;
		}
		mtx_lock(&sc->lock);
		if (sc->stopping) {
			mtx_unlock(&sc->lock);
			error = ENXIO;
			break;
		}
		if (bp->bio_length == 0) {
			mtx_unlock(&sc->lock);
			error = 0;
			break;
		}
		/* Queue upstream BIOs directly; no per-request payload allocation. */
		bioq_insert_tail(&sc->queue, bp);
		wakeup_one(sc);
		mtx_unlock(&sc->lock);
		return;
	default:
		/* Never forward a control request to the backing provider. */
		error = EOPNOTSUPP;
		break;
	}
	bp->bio_completed = 0;
	g_io_deliver(bp, error);
}

int
g_verity_provider_destroy(struct g_geom *gp)
{
	struct verity_softc *sc;
	struct g_provider *pp;

	g_topology_assert();
	if (gp == NULL || gp->class != &g_verity_class || gp->softc == NULL)
		return (EINVAL);
	sc = gp->softc;
	pp = sc->provider;
	if (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0))
		return (EBUSY);
	verity_stop(sc);
	return (0);
}

/*
 * Identify the live verifier object, never a device pathname or class name.
 * Caller holds topology and owns a reference keeping pp alive. This is a copy
 * of constructor input, not proof that its signer is authorized for boot.
 */
int
g_verity_provider_root(struct g_provider *pp, struct g_verity_root *root)
{
	struct verity_softc *sc;

	g_topology_assert();
	if (pp == NULL || root == NULL || pp->geom == NULL ||
	    pp->geom->class != &g_verity_class)
		return (EINVAL);
	sc = pp->geom->softc;
	if (sc == NULL || sc->stopping || sc->provider != pp || sc->allocated == 0)
		return (ENXIO);
	/* Worker root copies are immutable for the binding's lifetime. */
	*root = sc->workers[0].cache.root;
	return (0);
}

/* Boot/construction preflight: the same calculation drives actual allocation. */
int
g_verity_provider_resources(const struct g_verity_root *root, unsigned workers,
    uint64_t cache_entries, uint64_t window_size, uint64_t buffer_budget,
    size_t *per_worker_out)
{
	struct g_verity_cache check;
	size_t block, per_worker;
	int error;

	if (root == NULL || per_worker_out == NULL || workers == 0 || workers > MAXCPU)
		return (EINVAL);
	if (cache_entries > SIZE_MAX || window_size > SIZE_MAX || buffer_budget > SIZE_MAX)
		return (EOVERFLOW);
	error = g_verity_cache_init(&check, root, NULL, NULL, 0);
	if (error != 0)
		return (error);
	block = root->layout.block_size;
	if (window_size < block || window_size > (uint64_t)maxphys ||
	    window_size % block != 0 || window_size > SIZE_MAX - 2 * block ||
	    cache_entries > (SIZE_MAX - 2 * block - window_size) /
	    (block + sizeof(uint64_t)))
		return (EINVAL);
	per_worker = cache_entries * (block + sizeof(uint64_t)) + 2 * block + window_size;
	if (per_worker > SIZE_MAX - sizeof(struct verity_worker) ||
	    buffer_budget < sizeof(struct verity_softc) || workers >
	    (buffer_budget - sizeof(struct verity_softc)) /
	    (per_worker + sizeof(struct verity_worker)))
		return (ENOMEM);
	*per_worker_out = per_worker;
	return (0);
}

int
g_verity_provider_create(struct g_provider *backing, const char *name,
    const struct g_verity_root *root, unsigned workers, size_t cache_entries,
    size_t window_size, size_t buffer_budget, struct g_provider **result)
{
	struct verity_softc *sc;
	struct verity_worker *worker;
	struct g_geom *gp;
	struct g_consumer *cp;
	struct g_provider *pp;
	uint64_t *tags;
	void *blocks;
	size_t per_worker, block;
	unsigned i;
	int error;

	g_topology_assert();
	if (backing == NULL || name == NULL || name[0] == '\0' ||
	    result == NULL || root == NULL || workers == 0 || workers > MAXCPU)
		return (EINVAL);
	error = g_verity_provider_resources(root, workers, cache_entries,
	    window_size, buffer_budget, &per_worker);
	if (error != 0)
		return (error);
	block = root->layout.block_size;
	if (g_provider_by_name(name) != NULL)
		return (EEXIST);
	sc = malloc(sizeof(*sc), M_VERITY, M_WAITOK | M_ZERO);
	mtx_init(&sc->lock, "verity queue", NULL, MTX_DEF);
	bioq_init(&sc->queue);
	/* g_access may drop topology: orphan callbacks must not free sc yet. */
	sc->running = 1;
	sc->window_size = window_size;
	sc->workers = mallocarray(workers, sizeof(*worker), M_VERITY,
	    M_WAITOK | M_ZERO);
	gp = g_new_geomf(&g_verity_class, "%s", name);
	gp->softc = sc;
	sc->geom = gp;
	cp = g_new_consumer(gp);
	error = g_attach(cp, backing);
	if (error != 0)
		goto fail;
	/* Pin storage and exclude other GEOM writers for this binding's lifetime. */
	error = g_access(cp, 1, 0, 1);
	if (error != 0)
		goto fail;
	/* Access methods may drop topology while opening backing storage. */
	if (sc->stopping) {
		error = ENXIO;
		goto fail;
	}
	error = g_verity_backing_bind(&sc->backing, cp,
	    root->layout.data_bytes, root->layout.block_size);
	if (error != 0)
		goto fail;
	for (i = 0; i < workers; i++) {
		worker = &sc->workers[i];
		worker->sc = sc;
		worker->allocation = malloc(per_worker, M_VERITY, M_WAITOK);
		tags = worker->allocation;
		blocks = (char *)tags + cache_entries * sizeof(*tags);
		worker->data = (char *)blocks + cache_entries * block;
		worker->hashes = (char *)worker->data + block;
		worker->window = (char *)worker->hashes + block;
		error = g_verity_cache_init(&worker->cache, root, tags, blocks,
		    cache_entries);
		KASSERT(error == 0, ("validated verity cache initialization"));
		mtx_lock(&sc->lock);
		sc->running++;
		mtx_unlock(&sc->lock);
		error = kproc_create(verity_worker, worker, NULL, 0, 0,
		    "gverity %u", i);
		if (error != 0) {
			mtx_lock(&sc->lock);
			sc->running--;
			mtx_unlock(&sc->lock);
			free(worker->allocation, M_VERITY);
			worker->allocation = NULL;
			goto fail;
		}
		sc->allocated++;
	}
	pp = g_new_providerf(gp, "%s", name);
	pp->mediasize = root->layout.data_bytes;
	pp->sectorsize = backing->sectorsize;
	sc->provider = pp;
	g_error_provider(pp, 0);
	*result = pp;
	verity_constructor_done(sc);
	return (0);
fail:
	verity_stop(sc);
	verity_constructor_done(sc);
	return (error);
}

static struct g_class g_verity_class = {
	.name = "VERITY",
	.version = G_VERSION,
	.start = verity_start,
	.access = verity_access,
	.orphan = verity_orphan,
	.spoiled = verity_orphan,
	.resize = verity_resize,
	.providergone = verity_providergone,
};
DECLARE_GEOM_CLASS(g_verity_class, g_verity);
