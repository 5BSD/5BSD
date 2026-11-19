/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 */

static int dtrace_verbose_ioctl;
SYSCTL_INT(_debug_dtrace, OID_AUTO, verbose_ioctl, CTLFLAG_RW,
    &dtrace_verbose_ioctl, 0, "log DTrace ioctls");

#define DTRACE_IOCTL_PRINTF(fmt, ...)	if (dtrace_verbose_ioctl) printf(fmt, ## __VA_ARGS__ )

/*
 * 5BSD: DTRACEHIOC_ADDDOF for another process.  Upstream accepts it only
 * for a stopped, traced child of the caller, which made registering a
 * process's USDT probes a debugging operation: libdtrace attached with
 * ptrace, stopped the process and read its memory.  Here it needs the
 * DTrace process privilege and inspect permission (p_caninspect(9)), and
 * the target keeps running.
 *
 * The DOF is a program's own description of its probes; registering it
 * lets a consumer plant traps at the probe sites it names.  What it names
 * is bounded here, not trusted:
 *
 * - The DOF must lie in a read-only mapping whose own object is a file's
 *   vnode object (not an anonymous shadow: the process has not written its
 *   private copy).  This pins the DOF to an object, the file, so that the
 *   process cannot change what is read by changing its mapping after the
 *   check; it does not make the DOF trustworthy.  The DOF is then read from
 *   the file (vn_rdwr()), at the offsets that mapping covered, and never
 *   from the process's memory.
 * - The load base is derived here, not taken from the caller: the start of
 *   the mapping of the same vnode object at file offset 0 for an ET_DYN
 *   object, 0 for ET_EXEC.  A dofhp_addr that differs is refused.
 * - Every probe and is-enabled site the DOF names, once relocated, must lie
 *   in an executable mapping of that file (dtrace_helper_slurp() checks
 *   them against the ranges recorded here): a DOF cannot name a site in
 *   another object, the stack or the heap.
 *
 * The target is held, with exec blocked, from the check to the
 * registration; exit waits for the hold ("exithold") before the fasttrap
 * exit hook, and the registration refuses a process that has begun to exit
 * (checked under dtrace_lock, which that hook takes), so no provider
 * outlives its process.
 *
 * Errors: EPERM (no PRIV_DTRACE_PROC, or the Unix debug rules), ECAPMODE
 * (the caller is in capability mode), ESRCH (no such process, or it is
 * exiting), EINVAL (a system process, a dofhp_addr that is not the load
 * base, not an ELF object, or a DOF the parser refuses), EACCES (a MAC
 * policy), EBUSY (exec in progress), EFAULT (the address is not in such a
 * mapping, the DOF extends past it, or a probe site lies outside the
 * object's executable mappings), E2BIG (DOF too large).
 */
SDT_PROVIDER_DEFINE(dtrace_helper);
/* target pid, errno */
SDT_PROBE_DEFINE2(dtrace_helper, , , adddof__other, "pid_t", "int");

/*
 * The object a DOF came from, as dtrace_adddof_object() found it under the
 * target's map lock.
 */
struct dtrace_adddof_obj {
	struct vnode		*dao_vp;	/* referenced */
	vm_ooffset_t		dao_off;	/* file offset of the DOF */
	vm_ooffset_t		dao_end;	/* file offset of its mapping's end */
	uintptr_t		dao_base;	/* start of the offset-0 mapping */
	bool			dao_hasbase;
	dtrace_helper_pcs_t	dao_pcs;	/* executable mappings */
};

/*
 * Whether the entry object obj is target or a private copy of it that the
 * process wrote (a breakpoint in its text), one shadow deep.  The entry holds
 * obj; its backing object pointer is only compared, never followed.
 */
static bool
dtrace_adddof_backed_by(vm_object_t obj, vm_object_t target)
{

	return (obj != NULL && (obj == target ||
	    atomic_load_ptr(&obj->backing_object) == target));
}

/*
 * Find the mapping of the DOF at uaddr in vm and the object behind it.
 * On success dao holds a reference on the file's vnode.
 */
static int
dtrace_adddof_object(struct vmspace *vm, uintptr_t uaddr,
    struct dtrace_adddof_obj *dao)
{
	vm_map_t map;
	vm_map_entry_t entry, e;
	vm_object_t obj;
	dtrace_helper_pcs_t *pcs;
	int error;

	map = &vm->vm_map;
	pcs = &dao->dao_pcs;
	error = EFAULT;
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, uaddr, &entry) ||
	    (entry->eflags & MAP_ENTRY_IS_SUB_MAP) != 0 ||
	    (obj = entry->object.vm_object) == NULL ||
	    (entry->protection & VM_PROT_WRITE) != 0 ||
	    entry->end - uaddr < sizeof(dof_hdr_t))
		goto out;
	/*
	 * The type of an object and OBJ_ANON never change.  The entry's
	 * reference on the object holds a use reference on its vnode, so the
	 * vnode stays allocated while the map is locked; a forced unmount may
	 * clear the handle, which is then refused.
	 */
	if (obj->type != OBJT_VNODE || (obj->flags & OBJ_ANON) != 0 ||
	    (dao->dao_vp = atomic_load_ptr(&obj->handle)) == NULL)
		goto out;
	vref(dao->dao_vp);
	dao->dao_off = entry->offset + (uaddr - entry->start);
	dao->dao_end = entry->offset + (entry->end - entry->start);

	/* The load base, and the executable mappings of the same file. */
	VM_MAP_ENTRY_FOREACH(e, map) {
		if ((e->eflags & MAP_ENTRY_IS_SUB_MAP) != 0)
			continue;
		if (e->object.vm_object == obj && e->offset == 0 &&
		    (!dao->dao_hasbase || e->start < dao->dao_base)) {
			dao->dao_base = e->start;
			dao->dao_hasbase = true;
		}
		if ((e->protection & VM_PROT_EXECUTE) != 0 &&
		    pcs->dhpc_n < DTRACE_HELPER_PCS_MAX &&
		    dtrace_adddof_backed_by(e->object.vm_object, obj)) {
			pcs->dhpc_start[pcs->dhpc_n] = e->start;
			pcs->dhpc_end[pcs->dhpc_n] = e->end;
			pcs->dhpc_n++;
		}
	}
	error = 0;
out:
	vm_map_unlock_read(map);
	return (error);
}

static int
dtrace_adddof_read(struct thread *td, struct vnode *vp, void *buf,
    size_t len, vm_ooffset_t off)
{
	ssize_t resid;
	int error;

	error = vn_rdwr(UIO_READ, vp, buf, len, off, UIO_SYSSPACE,
	    IO_NOMACCHECK, td->td_ucred, NOCRED, &resid, td);
	if (error == 0 && resid != 0)
		error = EFAULT;
	return (error);
}

/*
 * The load base of the ELF object behind dao: the start of its mapping at
 * file offset 0 for ET_DYN, 0 for ET_EXEC.
 */
static int
dtrace_adddof_base(struct thread *td, struct dtrace_adddof_obj *dao,
    uint64_t *basep)
{
	unsigned char ident[EI_NIDENT + sizeof(uint16_t)];
	uint16_t type;
	int error;

	error = dtrace_adddof_read(td, dao->dao_vp, ident, sizeof(ident), 0);
	if (error != 0)
		return (error);
	if (memcmp(ident, ELFMAG, SELFMAG) != 0)
		return (EINVAL);
	memcpy(&type, ident + EI_NIDENT, sizeof(type));
	switch (type) {
	case ET_EXEC:
		*basep = 0;
		return (0);
	case ET_DYN:
		if (!dao->dao_hasbase)
			return (EFAULT);
		*basep = dao->dao_base;
		return (0);
	default:
		return (EINVAL);
	}
}

/* The DOF of dao, read from its file. */
static dof_hdr_t *
dtrace_adddof_copyin(struct thread *td, struct dtrace_adddof_obj *dao,
    int *errp)
{
	dof_hdr_t hdr, *dof;
	size_t loadsz;
	int error;

	error = dtrace_adddof_read(td, dao->dao_vp, &hdr, sizeof(hdr),
	    dao->dao_off);
	if (error != 0) {
		dtrace_dof_error(NULL, "failed to read DOF header");
		*errp = error;
		return (NULL);
	}
	if (hdr.dofh_loadsz >= dtrace_dof_maxsize) {
		dtrace_dof_error(&hdr, "load size exceeds maximum");
		*errp = E2BIG;
		return (NULL);
	}
	loadsz = (size_t)hdr.dofh_loadsz;
	if (loadsz < sizeof(hdr)) {
		dtrace_dof_error(&hdr, "invalid load size");
		*errp = EINVAL;
		return (NULL);
	}
	if (loadsz > dao->dao_end - dao->dao_off) {
		dtrace_dof_error(&hdr, "DOF extends past its mapping");
		*errp = EFAULT;
		return (NULL);
	}
	dof = kmem_alloc(loadsz, KM_SLEEP);
	error = dtrace_adddof_read(td, dao->dao_vp, dof, loadsz, dao->dao_off);
	if (error == 0 && dof->dofh_loadsz != loadsz)
		error = EFAULT;	/* the file changed between the reads */
	if (error != 0) {
		kmem_free(dof, loadsz);
		*errp = error;
		return (NULL);
	}
	return (dof);
}

static int
dtrace_adddof_other(struct thread *td, dof_helper_t *dhp)
{
	struct dtrace_adddof_obj dao;
	struct vmspace *vm;
	struct proc *p;
	dof_hdr_t *dof;
	uint64_t base;
	bool exiting;
	int error, rval;

	dof = NULL;
	memset(&dao, 0, sizeof(dao));
	if (IN_CAPABILITY_MODE(td)) {
		error = ECAPMODE;
		goto out;
	}
	error = priv_check(td, DTRACE_FREEBSD_PRIV_PROC);
	if (error != 0)
		goto out;
	error = pget(dhp->dofhp_pid, PGET_HOLD | PGET_NOTWEXIT | PGET_NOTID,
	    &p);
	if (error != 0)
		goto out;
	PROC_LOCK(p);
	if ((p->p_flag & P_SYSTEM) != 0) {
		/* No USDT; an aio daemon's p_vmspace may be borrowed. */
		_PRELE(p);
		PROC_UNLOCK(p);
		error = EINVAL;
		goto out;
	}
	execve_block_wait(td, p);
	error = p_caninspect(td, p);
	PROC_UNLOCK(p);
	vm = NULL;
	if (error == 0 && (vm = vmspace_acquire_ref(p)) == NULL)
		error = ESRCH;
	if (error == 0)
		error = dtrace_adddof_object(vm, (uintptr_t)dhp->dofhp_dof,
		    &dao);
	if (vm != NULL)
		vmspace_free(vm);
	if (error == 0)
		error = dtrace_adddof_base(td, &dao, &base);
	if (error == 0 && dhp->dofhp_addr != base)
		error = EINVAL;
	if (error == 0)
		dof = dtrace_adddof_copyin(td, &dao, &error);
	if (dao.dao_vp != NULL)
		vrele(dao.dao_vp);
	if (dof != NULL) {
		mutex_enter(&dtrace_lock);
		PROC_LOCK(p);
		exiting = (p->p_flag & P_WEXIT) != 0;
		PROC_UNLOCK(p);
		if (exiting) {
			dtrace_dof_destroy(dof);
			error = ESRCH;
		} else if ((rval = dtrace_helper_slurp(dof, dhp, p,
		    &dao.dao_pcs)) != -1) {
			dhp->dofhp_gen = rval;
			error = 0;
		} else
			error = dao.dao_pcs.dhpc_error != 0 ?
			    dao.dao_pcs.dhpc_error : EINVAL;
		mutex_exit(&dtrace_lock);
	}
	PROC_LOCK(p);
	execve_unblock(td, p);
	_PRELE(p);
	PROC_UNLOCK(p);
out:
	SDT_PROBE2(dtrace_helper, , , adddof__other, dhp->dofhp_pid, error);
	return (error);
}

static int
dtrace_ioctl_helper(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct proc *p;
	dof_helper_t *dhp;
	dof_hdr_t *dof;
	int rval;

	dhp = NULL;
	dof = NULL;
	rval = 0;
	switch (cmd) {
	case DTRACEHIOC_ADDDOF:
		dhp = (dof_helper_t *)addr;
		addr = (caddr_t)(uintptr_t)dhp->dofhp_dof;
		p = curproc;
		if (p->p_pid != dhp->dofhp_pid) {
			rval = dtrace_adddof_other(td, dhp);
			break;
		}
		dof = dtrace_dof_copyin((uintptr_t)addr, &rval);
		if (dof == NULL)
			break;

		mutex_enter(&dtrace_lock);
		if ((rval = dtrace_helper_slurp(dof, dhp, p, NULL)) != -1) {
			dhp->dofhp_gen = rval;
			rval = 0;
		} else {
			rval = EINVAL;
		}
		mutex_exit(&dtrace_lock);
		break;
	case DTRACEHIOC_REMOVE:
		mutex_enter(&dtrace_lock);
		rval = dtrace_helper_destroygen(NULL, *(int *)(uintptr_t)addr);
		mutex_exit(&dtrace_lock);
		break;
	default:
		rval = ENOTTY;
		break;
	}
	return (rval);
}

/* ARGSUSED */
static int
dtrace_ioctl(struct cdev *dev, u_long cmd, caddr_t addr,
    int flags __unused, struct thread *td)
{
	dtrace_state_t *state;
	devfs_get_cdevpriv((void **) &state);

	int error = 0;
	if (state == NULL)
		return (EINVAL);

	if (state->dts_anon) {
		ASSERT(dtrace_anon.dta_state == NULL);
		state = state->dts_anon;
	}

	switch (cmd) {
	case DTRACEIOC_AGGDESC: {
		dtrace_aggdesc_t **paggdesc = (dtrace_aggdesc_t **) addr;
		dtrace_aggdesc_t aggdesc;
		dtrace_action_t *act;
		dtrace_aggregation_t *agg;
		int nrecs;
		uint32_t offs;
		dtrace_recdesc_t *lrec;
		void *buf;
		size_t size;
		uintptr_t dest;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_AGGDESC\n",__func__,__LINE__);

		if (copyin((void *) *paggdesc, &aggdesc, sizeof (aggdesc)) != 0)
			return (EFAULT);

		mutex_enter(&dtrace_lock);

		if ((agg = dtrace_aggid2agg(state, aggdesc.dtagd_id)) == NULL) {
			mutex_exit(&dtrace_lock);
			return (EINVAL);
		}

		aggdesc.dtagd_epid = agg->dtag_ecb->dte_epid;

		nrecs = aggdesc.dtagd_nrecs;
		aggdesc.dtagd_nrecs = 0;

		offs = agg->dtag_base;
		lrec = &agg->dtag_action.dta_rec;
		aggdesc.dtagd_size = lrec->dtrd_offset + lrec->dtrd_size - offs;

		for (act = agg->dtag_first; ; act = act->dta_next) {
			ASSERT(act->dta_intuple ||
			    DTRACEACT_ISAGG(act->dta_kind));

			/*
			 * If this action has a record size of zero, it
			 * denotes an argument to the aggregating action.
			 * Because the presence of this record doesn't (or
			 * shouldn't) affect the way the data is interpreted,
			 * we don't copy it out to save user-level the
			 * confusion of dealing with a zero-length record.
			 */
			if (act->dta_rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			aggdesc.dtagd_nrecs++;

			if (act == &agg->dtag_action)
				break;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof (dtrace_aggdesc_t) +
		    (aggdesc.dtagd_nrecs * sizeof (dtrace_recdesc_t));

		buf = kmem_alloc(size, KM_SLEEP);
		dest = (uintptr_t)buf;

		bcopy(&aggdesc, (void *)dest, sizeof (aggdesc));
		dest += offsetof(dtrace_aggdesc_t, dtagd_rec[0]);

		for (act = agg->dtag_first; ; act = act->dta_next) {
			dtrace_recdesc_t rec = act->dta_rec;

			/*
			 * See the comment in the above loop for why we pass
			 * over zero-length records.
			 */
			if (rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			if (nrecs-- == 0)
				break;

			rec.dtrd_offset -= offs;
			bcopy(&rec, (void *)dest, sizeof (rec));
			dest += sizeof (dtrace_recdesc_t);

			if (act == &agg->dtag_action)
				break;
		}

		mutex_exit(&dtrace_lock);

		if (copyout(buf, (void *) *paggdesc, dest - (uintptr_t)buf) != 0) {
			kmem_free(buf, size);
			return (EFAULT);
		}

		kmem_free(buf, size);
		return (0);
	}
	case DTRACEIOC_AGGSNAP:
	case DTRACEIOC_BUFSNAP: {
		dtrace_bufdesc_t **pdesc = (dtrace_bufdesc_t **) addr;
		dtrace_bufdesc_t desc;
		caddr_t cached;
		dtrace_buffer_t *buf;

		dtrace_debug_output();

		if (copyin((void *) *pdesc, &desc, sizeof (desc)) != 0)
			return (EFAULT);

		DTRACE_IOCTL_PRINTF("%s(%d): %s curcpu %d cpu %d\n",
		    __func__,__LINE__,
		    cmd == DTRACEIOC_AGGSNAP ?
		    "DTRACEIOC_AGGSNAP":"DTRACEIOC_BUFSNAP",
		    curcpu, desc.dtbd_cpu);

		if (desc.dtbd_cpu > mp_maxid || CPU_ABSENT(desc.dtbd_cpu))
			return (ENOENT);

		mutex_enter(&dtrace_lock);

		if (cmd == DTRACEIOC_BUFSNAP) {
			buf = &state->dts_buffer[desc.dtbd_cpu];
		} else {
			buf = &state->dts_aggbuffer[desc.dtbd_cpu];
		}

		if (buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL)) {
			size_t sz = buf->dtb_offset;

			if (state->dts_activity != DTRACE_ACTIVITY_STOPPED) {
				mutex_exit(&dtrace_lock);
				return (EBUSY);
			}

			/*
			 * If this buffer has already been consumed, we're
			 * going to indicate that there's nothing left here
			 * to consume.
			 */
			if (buf->dtb_flags & DTRACEBUF_CONSUMED) {
				mutex_exit(&dtrace_lock);

				desc.dtbd_size = 0;
				desc.dtbd_drops = 0;
				desc.dtbd_errors = 0;
				desc.dtbd_oldest = 0;
				sz = sizeof (desc);

				if (copyout(&desc, (void *) *pdesc, sz) != 0)
					return (EFAULT);

				return (0);
			}

			/*
			 * If this is a ring buffer that has wrapped, we want
			 * to copy the whole thing out.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				dtrace_buffer_polish(buf);
				sz = buf->dtb_size;
			}

			if (copyout(buf->dtb_tomax, desc.dtbd_data, sz) != 0) {
				mutex_exit(&dtrace_lock);
				return (EFAULT);
			}

			desc.dtbd_size = sz;
			desc.dtbd_drops = buf->dtb_drops;
			desc.dtbd_errors = buf->dtb_errors;
			desc.dtbd_oldest = buf->dtb_xamot_offset;
			desc.dtbd_timestamp = dtrace_gethrtime();

			mutex_exit(&dtrace_lock);

			if (copyout(&desc, (void *) *pdesc, sizeof (desc)) != 0)
				return (EFAULT);

			buf->dtb_flags |= DTRACEBUF_CONSUMED;

			return (0);
		}

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			mutex_exit(&dtrace_lock);
			return (ENOENT);
		}

		cached = buf->dtb_tomax;
		ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));

		dtrace_xcall(desc.dtbd_cpu,
		    (dtrace_xcall_t)dtrace_buffer_switch, buf);

		state->dts_errors += buf->dtb_xamot_errors;

		/*
		 * If the buffers did not actually switch, then the cross call
		 * did not take place -- presumably because the given CPU is
		 * not in the ready set.  If this is the case, we'll return
		 * ENOENT.
		 */
		if (buf->dtb_tomax == cached) {
			ASSERT(buf->dtb_xamot != cached);
			mutex_exit(&dtrace_lock);
			return (ENOENT);
		}

		ASSERT(cached == buf->dtb_xamot);

		DTRACE_IOCTL_PRINTF("%s(%d): copyout the buffer snapshot\n",__func__,__LINE__);

		/*
		 * We have our snapshot; now copy it out.
		 */
		if (copyout(buf->dtb_xamot, desc.dtbd_data,
		    buf->dtb_xamot_offset) != 0) {
			mutex_exit(&dtrace_lock);
			return (EFAULT);
		}

		desc.dtbd_size = buf->dtb_xamot_offset;
		desc.dtbd_drops = buf->dtb_xamot_drops;
		desc.dtbd_errors = buf->dtb_xamot_errors;
		desc.dtbd_oldest = 0;
		desc.dtbd_timestamp = buf->dtb_switched;

		mutex_exit(&dtrace_lock);

		DTRACE_IOCTL_PRINTF("%s(%d): copyout buffer desc: size %zd drops %lu errors %lu\n",__func__,__LINE__,(size_t) desc.dtbd_size,(u_long) desc.dtbd_drops,(u_long) desc.dtbd_errors);

		/*
		 * Finally, copy out the buffer description.
		 */
		if (copyout(&desc, (void *) *pdesc, sizeof (desc)) != 0)
			return (EFAULT);

		return (0);
	}
	case DTRACEIOC_CONF: {
		dtrace_conf_t conf;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_CONF\n",__func__,__LINE__);

		bzero(&conf, sizeof (conf));
		conf.dtc_difversion = DIF_VERSION;
		conf.dtc_difintregs = DIF_DIR_NREGS;
		conf.dtc_diftupregs = DIF_DTR_NREGS;
		conf.dtc_ctfmodel = CTF_MODEL_NATIVE;

		*((dtrace_conf_t *) addr) = conf;

		return (0);
	}
	case DTRACEIOC_DOFGET: {
		dof_hdr_t **pdof = (dof_hdr_t **) addr;
		dof_hdr_t hdr, *dof = *pdof;
		int rval;
		uint64_t len;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_DOFGET\n",__func__,__LINE__);

		if (copyin((void *)dof, &hdr, sizeof (hdr)) != 0)
			return (EFAULT);

		mutex_enter(&dtrace_lock);
		dof = dtrace_dof_create(state);
		mutex_exit(&dtrace_lock);

		len = MIN(hdr.dofh_loadsz, dof->dofh_loadsz);
		rval = copyout(dof, (void *) *pdof, len);
		dtrace_dof_destroy(dof);

		return (rval == 0 ? 0 : EFAULT);
	}
	case DTRACEIOC_ENABLE: {
		dof_hdr_t *dof = NULL;
		dtrace_enabling_t *enab = NULL;
		dtrace_vstate_t *vstate;
		int err = 0;
		int rval;
		int ndesc = 0;
		int i;
		dtrace_epid_t first_epid;
		dtrace_epid_t initial_last_epid;
		dtrace_epid_t late_first_epid;
		size_t pbbufsize = 0;
		dtrace_probedesc_t *probes = NULL;
		dtrace_enable_io_t *p = (dtrace_enable_io_t *) addr;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_ENABLE\n",__func__,__LINE__);

		/*
		 * If a NULL argument has been passed, we take this as our
		 * cue to reevaluate our enablings.
		 */
		if (p->dof == NULL) {
			dtrace_enabling_matchall();

			return (0);
		}

		p->n_matched = 0;
		p->n_desc = 0;
		if ((dof = dtrace_dof_copyin((uintptr_t)p->dof, &rval)) == NULL)
			return (EINVAL);

		mutex_enter(&cpu_lock);
		mutex_enter(&dtrace_lock);
		if (p->vmid != 0) {
			err = hypertrace_check_epoch == NULL ? ENOTSUP :
			    hypertrace_check_epoch(p->vmid, p->epoch);
			if (err != 0) {
				mutex_exit(&dtrace_lock);
				mutex_exit(&cpu_lock);
				dtrace_dof_destroy(dof);
				return (err);
			}
		}
		vstate = &state->dts_vstate;
		dtrace_curvmid = p->vmid;

		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE ||
		    state->dts_enable_pending) {
			dtrace_curvmid = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (EBUSY);
		}

		if (dtrace_dof_slurp(dof, vstate, td->td_ucred, &enab, 0, 0,
		    B_TRUE) != 0) {
			dtrace_curvmid = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (EINVAL);
		}
		/* The probe VMID describes where a probe fires; this identity
		 * describes the VM that supplied the program, including host probes. */
		enab->dten_origin_vmid = p->vmid;
		enab->dten_origin_epoch = p->vmid == 0 ? 0 : p->epoch;

		if ((rval = dtrace_dof_options(dof, state)) != 0) {
			dtrace_enabling_destroy(enab);
			dtrace_curvmid = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (rval);
		}

		first_epid = state->dts_epid;
		if ((err = dtrace_enabling_match(enab, &p->n_matched)) == 0) {
			if (p->n_matched > 0 && p->ps != NULL) {
				/*
				 * Patch up our probes so that userspace knows
				 * what was enabled.
				 */
				probes = dtrace_enabling_list(
				    enab, &ndesc, &pbbufsize, &err);
				if (probes == NULL)
					;	/* ENOMEM or ENAMETOOLONG */
				else if (ndesc > p->n_matched)
					err = EINTEGRITY;
				else if (p->ps_bufsize < 0 ||
				    (size_t)ndesc > (size_t)p->ps_bufsize /
				    sizeof(dtrace_probedesc_t))
					err = E2BIG;
				else
					p->n_desc = ndesc;
			}
			if (err == 0)
				err = dtrace_enabling_retain(enab);
		}
		if (err == 0 && probes != NULL) {
			/* Matchall must not extend this enabling while its caller can
			 * still reject the probe list. GO and another ENABLE on this
			 * state wait for the copyout result. */
			ASSERT(state->dts_enable_pending == 0);
			enab->dten_pending = 1;
			state->dts_enable_pending = 1;
		}
		initial_last_epid = state->dts_epid;
		if (err != 0) {
			dtrace_enabling_rollback(state, first_epid,
			    state->dts_epid);
			dtrace_enabling_destroy(enab);
			p->n_matched = 0;
			p->n_desc = 0;
		}

		dtrace_curvmid = 0;
		mutex_exit(&dtrace_lock);
		mutex_exit(&cpu_lock);

		if (err == 0 && probes != NULL) {
			err = copyout(probes, p->ps,
			    (size_t)ndesc * sizeof(dtrace_probedesc_t));
			mutex_enter(&cpu_lock);
			mutex_enter(&dtrace_lock);
			ASSERT(state->dts_enable_pending && enab->dten_pending);
			ASSERT(state->dts_activity == DTRACE_ACTIVITY_INACTIVE);
			late_first_epid = state->dts_epid;
			if (err == 0 && p->vmid != 0)
				err = hypertrace_check_epoch == NULL ? ENOTSUP :
				    hypertrace_check_epoch(p->vmid, p->epoch);
			if (err == 0) {
				/* A provider may have appeared while copyout ran. */
				dtrace_curvmid = p->vmid;
				err = dtrace_enabling_match(enab, NULL);
				dtrace_curvmid = 0;
			}
			if (err != 0) {
				dtrace_enabling_rollback(state, late_first_epid,
				    state->dts_epid);
				dtrace_enabling_rollback(state, first_epid,
				    initial_last_epid);
				dtrace_enabling_destroy(enab);
				p->n_matched = 0;
				p->n_desc = 0;
			} else {
				enab->dten_pending = 0;
			}
			state->dts_enable_pending = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
		}

		if (probes)
			kmem_free(probes, pbbufsize);
		dtrace_dof_destroy(dof);

		return (err);
	}
	case DTRACEIOC_EPROBE: {
		dtrace_eprobedesc_t **pepdesc = (dtrace_eprobedesc_t **) addr;
		dtrace_eprobedesc_t epdesc;
		dtrace_ecb_t *ecb;
		dtrace_action_t *act;
		void *buf;
		size_t size;
		uintptr_t dest;
		int nrecs;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_EPROBE\n",__func__,__LINE__);

		if (copyin((void *)*pepdesc, &epdesc, sizeof (epdesc)) != 0)
			return (EFAULT);

		mutex_enter(&dtrace_lock);

		if ((ecb = dtrace_epid2ecb(state, epdesc.dtepd_epid)) == NULL) {
			mutex_exit(&dtrace_lock);
			return (EINVAL);
		}

		if (ecb->dte_probe == NULL) {
			mutex_exit(&dtrace_lock);
			return (EINVAL);
		}

		epdesc.dtepd_probeid = ecb->dte_probe->dtpr_id;
		epdesc.dtepd_uarg = ecb->dte_uarg;
		epdesc.dtepd_size = ecb->dte_size;
		epdesc.dtepd_vmid = ecb->dte_probe->dtpr_vmid;

		nrecs = epdesc.dtepd_nrecs;
		epdesc.dtepd_nrecs = 0;
		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			epdesc.dtepd_nrecs++;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof (dtrace_eprobedesc_t) +
		    (epdesc.dtepd_nrecs * sizeof (dtrace_recdesc_t));

		buf = kmem_alloc(size, KM_SLEEP);
		dest = (uintptr_t)buf;

		bcopy(&epdesc, (void *)dest, sizeof (epdesc));
		dest += offsetof(dtrace_eprobedesc_t, dtepd_rec[0]);

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			if (nrecs-- == 0)
				break;

			bcopy(&act->dta_rec, (void *)dest,
			    sizeof (dtrace_recdesc_t));
			dest += sizeof (dtrace_recdesc_t);
		}

		mutex_exit(&dtrace_lock);

		if (copyout(buf, (void *) *pepdesc, dest - (uintptr_t)buf) != 0) {
			kmem_free(buf, size);
			return (EFAULT);
		}

		kmem_free(buf, size);
		return (0);
	}
	case DTRACEIOC_FORMAT: {
		dtrace_fmtdesc_t *fmt = (dtrace_fmtdesc_t *) addr;
		char *str;
		int len;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_FORMAT\n",__func__,__LINE__);

		mutex_enter(&dtrace_lock);

		if (fmt->dtfd_format == 0 ||
		    fmt->dtfd_format > state->dts_nformats) {
			mutex_exit(&dtrace_lock);
			return (EINVAL);
		}

		/*
		 * Format strings are allocated contiguously and they are
		 * never freed; if a format index is less than the number
		 * of formats, we can assert that the format map is non-NULL
		 * and that the format for the specified index is non-NULL.
		 */
		ASSERT(state->dts_formats != NULL);
		str = state->dts_formats[fmt->dtfd_format - 1];
		ASSERT(str != NULL);

		len = strlen(str) + 1;

		if (len > fmt->dtfd_length) {
			fmt->dtfd_length = len;
		} else {
			if (copyout(str, fmt->dtfd_string, len) != 0) {
				mutex_exit(&dtrace_lock);
				return (EINVAL);
			}
		}

		mutex_exit(&dtrace_lock);
		return (0);
	}
	case DTRACEIOC_GO: {
		int rval;
		processorid_t *cpuid = (processorid_t *) addr;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_GO\n",__func__,__LINE__);

		rval = dtrace_state_go(state, cpuid);
		return (rval);
	}
	case DTRACEIOC_PROBEARG: {
		dtrace_argdesc_t *desc = (dtrace_argdesc_t *) addr;
		dtrace_probe_t *probe;
		dtrace_provider_t *prov;
		dtrace_probe_t **dtrace_probes;
		int dtrace_nprobes;

		dtrace_probes = dtrace_vprobes[HYPERTRACE_HOSTID];
		dtrace_nprobes = dtrace_nvprobes[HYPERTRACE_HOSTID];

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_PROBEARG\n",__func__,__LINE__);

		if (desc->dtargd_id == DTRACE_IDNONE)
			return (EINVAL);

		if (desc->dtargd_ndx == DTRACE_ARGNONE)
			return (EINVAL);

		mutex_enter(&dtrace_provider_lock);
#ifdef illumos
		mutex_enter(&mod_lock);
#endif
		mutex_enter(&dtrace_lock);

		if (desc->dtargd_id > dtrace_nprobes) {
			mutex_exit(&dtrace_lock);
#ifdef illumos
			mutex_exit(&mod_lock);
#endif
			mutex_exit(&dtrace_provider_lock);
			return (EINVAL);
		}

		if ((probe = dtrace_probes[desc->dtargd_id - 1]) == NULL) {
			mutex_exit(&dtrace_lock);
#ifdef illumos
			mutex_exit(&mod_lock);
#endif
			mutex_exit(&dtrace_provider_lock);
			return (EINVAL);
		}

		mutex_exit(&dtrace_lock);

		prov = (dtrace_provider_t *)probe->dtpr_provider;

		if (prov->dtpv_pops.dtps_getargdesc == NULL) {
			/*
			 * There isn't any typed information for this probe.
			 * Set the argument number to DTRACE_ARGNONE.
			 */
			desc->dtargd_ndx = DTRACE_ARGNONE;
		} else {
			desc->dtargd_native[0] = '\0';
			desc->dtargd_xlate[0] = '\0';
			desc->dtargd_mapping = desc->dtargd_ndx;

			prov->dtpv_pops.dtps_getargdesc(prov->dtpv_arg,
			    probe->dtpr_id, probe->dtpr_arg, desc);
		}

#ifdef illumos
		mutex_exit(&mod_lock);
#endif
		mutex_exit(&dtrace_provider_lock);

		return (0);
	}
	case DTRACEIOC_PROBEMATCH:
	case DTRACEIOC_PROBES: {
		dtrace_probedesc_t *p_desc = (dtrace_probedesc_t *) addr;
		dtrace_probe_t *probe = NULL;
		dtrace_probekey_t pkey;
		dtrace_id_t i;
		int m = 0;
		uint32_t priv = 0;
		uid_t uid = 0;
		zoneid_t zoneid = 0;
		dtrace_vmid_t vmid;

		DTRACE_IOCTL_PRINTF("%s(%d): %s\n",__func__,__LINE__,
		    cmd == DTRACEIOC_PROBEMATCH ?
		    "DTRACEIOC_PROBEMATCH":"DTRACEIOC_PROBES");

		p_desc->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		p_desc->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		p_desc->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		p_desc->dtpd_name[DTRACE_NAMELEN - 1] = '\0';
		vmid = p_desc->dtpd_vmid;
		/* The VM identifier indexes the per-VM probe tables. */
		if (vmid >= HYPERTRACE_MAX_VMS)
			return (EINVAL);

		/*
		 * Before we attempt to match this probe, we want to give
		 * all providers the opportunity to provide it.
		 */
		if (p_desc->dtpd_id == DTRACE_IDNONE) {
			mutex_enter(&dtrace_provider_lock);
			dtrace_probe_provide(p_desc, NULL);
			mutex_exit(&dtrace_provider_lock);
			p_desc->dtpd_id++;
		}

		if (cmd == DTRACEIOC_PROBEMATCH)  {
			dtrace_probekey(p_desc, &pkey);
			pkey.dtpk_id = DTRACE_IDNONE;
		}

		dtrace_cred2priv(td->td_ucred, &priv, &uid, &zoneid);

		mutex_enter(&dtrace_lock);

		if (cmd == DTRACEIOC_PROBEMATCH) {
			for (i = p_desc->dtpd_id;
			    i <= dtrace_nvprobes[vmid]; i++) {
				if ((probe =
				    dtrace_vprobes[vmid][i - 1]) != NULL &&
				    (m = dtrace_match_probe(probe, &pkey,
				    priv, uid, zoneid)) != 0)
					break;
			}

			if (m < 0) {
				mutex_exit(&dtrace_lock);
				return (EINVAL);
			}

		} else {
			for (i = p_desc->dtpd_id;
			    i <= dtrace_nvprobes[vmid]; i++) {
				if ((probe =
				    dtrace_vprobes[vmid][i - 1]) != NULL &&
				    dtrace_match_priv(probe, priv, uid, zoneid))
					break;
			}
		}

		if (probe == NULL) {
			mutex_exit(&dtrace_lock);
			return (ESRCH);
		}

		dtrace_probe_description(probe, p_desc);
		mutex_exit(&dtrace_lock);

		return (0);
	}
	case DTRACEIOC_PROVIDER: {
		dtrace_providerdesc_t *pvd = (dtrace_providerdesc_t *) addr;
		dtrace_provider_t *pvp;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_PROVIDER\n",__func__,__LINE__);

		pvd->dtvd_name[DTRACE_PROVNAMELEN - 1] = '\0';
		mutex_enter(&dtrace_provider_lock);

		for (pvp = dtrace_provider; pvp != NULL; pvp = pvp->dtpv_next) {
			if (strcmp(pvp->dtpv_name, pvd->dtvd_name) == 0)
				break;
		}

		mutex_exit(&dtrace_provider_lock);

		if (pvp == NULL)
			return (ESRCH);

		bcopy(&pvp->dtpv_priv, &pvd->dtvd_priv, sizeof (dtrace_ppriv_t));
		bcopy(&pvp->dtpv_attr, &pvd->dtvd_attr, sizeof (dtrace_pattr_t));

		return (0);
	}
	case DTRACEIOC_REPLICATE: {
		dtrace_repldesc_t *desc = (dtrace_repldesc_t *) addr;
		dtrace_probedesc_t *match = &desc->dtrpd_match;
		dtrace_probedesc_t *create = &desc->dtrpd_create;
		int err;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_REPLICATE\n",__func__,__LINE__);

		match->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		match->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		match->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		match->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		create->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		create->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		create->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		create->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		mutex_enter(&dtrace_lock);
		err = state->dts_enable_pending ? EBUSY :
		    dtrace_enabling_replicate(state, match, create);
		mutex_exit(&dtrace_lock);

		return (err);
	}
	case DTRACEIOC_HANDLE_ID: {
		dtrace_handle_lifetime_t *identity = (void *)addr;
		mutex_enter(&dtrace_lock);
		memset(identity, 0, sizeof(*identity));
		memcpy(identity->generation, dtrace_handle_generation,
		    sizeof(identity->generation));
		identity->serial = state->dts_handle_serial;
		mutex_exit(&dtrace_lock);
		return (0);
	}
	case DTRACEIOC_HANDLE_QUERY:
		mutex_enter(&dtrace_lock);
		error = dtrace_handle_query((void *)addr);
		mutex_exit(&dtrace_lock);
		return (error);
	case DTRACEIOC_DRAINABLE:
		mutex_enter(&dtrace_lock);
		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE)
			error = EBUSY;
		else if (state->dts_speculates)
			error = EOPNOTSUPP;
		else
			error = 0;
		mutex_exit(&dtrace_lock);
		return (error);

	case DTRACEIOC_STATUS: {
		dtrace_status_t *stat = (dtrace_status_t *) addr;
		dtrace_dstate_t *dstate;
		int i, j;
		uint64_t nerrs;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_STATUS\n",__func__,__LINE__);

		/*
		 * See the comment in dtrace_state_deadman() for the reason
		 * for setting dts_laststatus to INT64_MAX before setting
		 * it to the correct value.
		 */
		state->dts_laststatus = INT64_MAX;
		dtrace_membar_producer();
		state->dts_laststatus = dtrace_gethrtime();

		bzero(stat, sizeof (*stat));

		mutex_enter(&dtrace_lock);

		if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
			mutex_exit(&dtrace_lock);
			return (ENOENT);
		}

		if (state->dts_activity == DTRACE_ACTIVITY_DRAINING)
			stat->dtst_exiting = 1;

		nerrs = state->dts_errors;
		dstate = &state->dts_vstate.dtvs_dynvars;

		CPU_FOREACH(i) {
			dtrace_dstate_percpu_t *dcpu = &dstate->dtds_percpu[i];

			stat->dtst_dyndrops += dcpu->dtdsc_drops;
			stat->dtst_dyndrops_dirty += dcpu->dtdsc_dirty_drops;
			stat->dtst_dyndrops_rinsing += dcpu->dtdsc_rinsing_drops;

			if (state->dts_buffer[i].dtb_flags & DTRACEBUF_FULL)
				stat->dtst_filled++;

			nerrs += state->dts_buffer[i].dtb_errors;

			for (j = 0; j < state->dts_nspeculations; j++) {
				dtrace_speculation_t *spec;
				dtrace_buffer_t *buf;

				spec = &state->dts_speculations[j];
				buf = &spec->dtsp_buffer[i];
				stat->dtst_specdrops += buf->dtb_xamot_drops;
			}
		}

		stat->dtst_specdrops_busy = state->dts_speculations_busy;
		stat->dtst_specdrops_unavail = state->dts_speculations_unavail;
		stat->dtst_stkstroverflows = state->dts_stkstroverflows;
		stat->dtst_dblerrors = state->dts_dblerrors;
		stat->dtst_killed =
		    (state->dts_activity == DTRACE_ACTIVITY_KILLED);
		stat->dtst_errors = nerrs;

		mutex_exit(&dtrace_lock);

		return (0);
	}
	case DTRACEIOC_STOP: {
		int rval;
		processorid_t *cpuid = (processorid_t *) addr;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_STOP\n",__func__,__LINE__);

		mutex_enter(&dtrace_lock);
		rval = dtrace_state_stop(state, cpuid);
		mutex_exit(&dtrace_lock);

		return (rval);
	}
	case DTRACEIOC_AUGMENT: {
		dof_hdr_t *dof = NULL;
		dtrace_enabling_t *enab = NULL;
		dtrace_vstate_t *vstate;
		int err = 0;
		int rval;
		dtrace_enable_io_t *p = (dtrace_enable_io_t *) addr;

		DTRACE_IOCTL_PRINTF("%s(%d): DTRACEIOC_AUGMENT\n",__func__,__LINE__);

		if (p->dof == NULL)
			return (EINVAL);

		if ((dof = dtrace_dof_copyin(
		    (uintptr_t)p->dof, &rval)) == NULL)
			return (EINVAL);

		mutex_enter(&cpu_lock);
		mutex_enter(&dtrace_lock);
		if (p->vmid != 0) {
			err = hypertrace_check_epoch == NULL ? ENOTSUP :
			    hypertrace_check_epoch(p->vmid, p->epoch);
			if (err != 0) {
				mutex_exit(&dtrace_lock);
				mutex_exit(&cpu_lock);
				dtrace_dof_destroy(dof);
				return (err);
			}
		}
		vstate = &state->dts_vstate;
		dtrace_curvmid = p->vmid;

		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE) {
			dtrace_curvmid = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (ESHUTDOWN);
		}

		if (dtrace_dof_slurp(dof, vstate, td->td_ucred, &enab, 0, 0,
		    B_TRUE) != 0) {
			dtrace_curvmid = 0;
			mutex_exit(&dtrace_lock);
			mutex_exit(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (EINVAL);
		}

		/*
		 * We don't allow changing options in this ioctl.
		 */
		if ((err = dtrace_enabling_match(enab, &p->n_matched)) == 0)
			err = dtrace_enabling_retain(enab);
		if (err != 0)
			dtrace_enabling_destroy(enab);

		dtrace_curvmid = 0;
		mutex_exit(&dtrace_lock);
		mutex_exit(&cpu_lock);
		dtrace_dof_destroy(dof);

		return (err);
	}
	case DTRACEIOC_VPROBE_CREATE: {
		dtrace_vprobe_io_t *p = (dtrace_vprobe_io_t *) addr;
		dtrace_probedesc_t *vprobes_to_create;
		size_t n_vprobes_to_create;
		int err;
		uint16_t vmid;

		err = 0;

		DTRACE_IOCTL_PRINTF(
		    "%s(%d): DTRACEIOC_VPROBE_CREATE\n", __func__, __LINE__);

		if (p->eprobes == NULL || p->neprobes == 0)
			return (EINVAL);

		if (p->vmid == 0 || p->vmid >= HYPERTRACE_MAX_VMS)
			return (EINVAL);

		vmid = p->vmid;
		n_vprobes_to_create = p->neprobes;
		/*
		 * We would overflow the integer, so we just return.
		 */
		if (n_vprobes_to_create >
		    (64U * 1024U * 1024U) / sizeof(dtrace_probedesc_t))
			return (EINVAL);

		vprobes_to_create = kmem_zalloc(
		    sizeof(dtrace_probedesc_t) * n_vprobes_to_create, KM_SLEEP);
		ASSERT(vprobes_to_create != NULL);
		ASSERT(n_vprobes_to_create != 0);

		if (copyin(p->eprobes, vprobes_to_create,
		    sizeof(dtrace_probedesc_t) * n_vprobes_to_create)) {
			kmem_free(vprobes_to_create,
			    sizeof(*vprobes_to_create) * n_vprobes_to_create);
			return (EFAULT);
		}

		dtrace_hypertrace_config_lock();

		if (state->dts_vprobe_registrations > DTRACE_SENSIBLE_PROBELIMIT ||
		    n_vprobes_to_create > DTRACE_SENSIBLE_PROBELIMIT -
		    state->dts_vprobe_registrations)
			err = ENOSPC;
		else
			err = hypertrace_create_probes == NULL ? ENOTSUP :
			    hypertrace_create_probes(vmid, p->epoch, vprobes_to_create,
			    n_vprobes_to_create);
		if (err == 0)
			dtrace_vprobe_register_owner(state, vmid, vprobes_to_create,
			    n_vprobes_to_create);

		dtrace_hypertrace_config_unlock();
		kmem_free(vprobes_to_create,
		    sizeof(*vprobes_to_create) * n_vprobes_to_create);

		return (err);
	}
	default:
		error = ENOTTY;
	}
	return (error);
}
