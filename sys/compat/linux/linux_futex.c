/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009-2021 Dmitry Chagin <dchagin@FreeBSD.org>
 * Copyright (c) 2008 Roman Divacky
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/umtxvar.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_futex.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_time.h>
#include <compat/linux/linux_util.h>

#define	FUTEX_SHARED	0x8     /* shared futex */
#define	FUTEX_UNOWNED	0

#define	GET_SHARED(a)	(a->flags & FUTEX_SHARED) ? AUTO_SHARE : THREAD_SHARE

static int futex_atomic_op(struct thread *, int, uint32_t *, int *);
static int handle_futex_death(struct thread *td, struct linux_emuldata *,
    uint32_t *, unsigned int, bool);
static int fetch_robust_entry(struct linux_robust_list **,
    struct linux_robust_list **, unsigned int *);

struct linux_futex_args {
	uint32_t	*uaddr;
	int32_t		op;
	uint32_t	flags;
	bool		clockrt;
	uint32_t	val;
	struct timespec	*ts;
	uint32_t	*uaddr2;
	uint32_t	val3;
	bool		val3_compare;
	struct timespec	kts;
};

static inline int futex_key_get(const void *, int, int, struct umtx_key *);
static void linux_umtx_abs_timeout_init(struct umtx_abs_timeout *,
	    struct linux_futex_args *);
static int linux_futex(struct thread *, struct linux_futex_args *);
static int linux_futex_op_wait(struct thread *, struct linux_futex_args *);
static int linux_futex_op_wake(struct thread *, struct linux_futex_args *);
static int linux_futex_op_requeue(struct thread *, struct linux_futex_args *);
static int linux_futex_wakeop(struct thread *, struct linux_futex_args *);
static int linux_futex_requeue_common(struct thread *, uint32_t *, int,
	    uint32_t *, int, int, int, uint32_t, bool);
static void linux_futex_lock2(struct umtx_key *, struct umtx_key *);
static void linux_futex_unlock2(struct umtx_key *, struct umtx_key *);
static int linux_futex2_share(uint32_t, int *);
static int linux_futex2_clock(l_int, bool *);
static int linux_futex_lock_pi(struct thread *, bool, struct linux_futex_args *);
static int linux_futex_unlock_pi(struct thread *, bool,
	    struct linux_futex_args *);
static int futex_wake_pi(struct thread *, uint32_t *, bool);

static int
futex_key_get(const void *uaddr, int type, int share, struct umtx_key *key)
{

	/* Check that futex address is a 32bit aligned. */
	if (!__is_aligned(uaddr, sizeof(uint32_t)))
		return (EINVAL);
	return (umtx_key_get(uaddr, type, share, key));
}

int
futex_wake(struct thread *td, uint32_t *uaddr, int val, bool shared)
{
	struct linux_futex_args args;

	bzero(&args, sizeof(args));
	args.op = LINUX_FUTEX_WAKE;
	args.uaddr = uaddr;
	args.flags = shared == true ? FUTEX_SHARED : 0;
	args.val = val;
	args.val3 = FUTEX_BITSET_MATCH_ANY;

	return (linux_futex_op_wake(td, &args));
}

static int
futex_wake_pi(struct thread *td, uint32_t *uaddr, bool shared)
{
	struct linux_futex_args args;

	bzero(&args, sizeof(args));
	args.op = LINUX_FUTEX_UNLOCK_PI;
	args.uaddr = uaddr;
	args.flags = shared == true ? FUTEX_SHARED : 0;

	return (linux_futex_unlock_pi(td, true, &args));
}

static int
futex_atomic_op(struct thread *td, int encoded_op, uint32_t *uaddr,
    int *res)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op << 8) >> 20;
	int cmparg = (encoded_op << 20) >> 20;
	int oldval = 0, ret;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

	switch (op) {
	case FUTEX_OP_SET:
		ret = futex_xchgl(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_ADD:
		ret = futex_addl(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_OR:
		ret = futex_orl(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_ANDN:
		ret = futex_andl(~oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_XOR:
		ret = futex_xorl(oparg, uaddr, &oldval);
		break;
	default:
		ret = ENOSYS;
		break;
	}

	if (ret != 0)
		return (ret);

	switch (cmp) {
	case FUTEX_OP_CMP_EQ:
		*res = (oldval == cmparg);
		break;
	case FUTEX_OP_CMP_NE:
		*res = (oldval != cmparg);
		break;
	case FUTEX_OP_CMP_LT:
		*res = (oldval < cmparg);
		break;
	case FUTEX_OP_CMP_GE:
		*res = (oldval >= cmparg);
		break;
	case FUTEX_OP_CMP_LE:
		*res = (oldval <= cmparg);
		break;
	case FUTEX_OP_CMP_GT:
		*res = (oldval > cmparg);
		break;
	default:
		ret = ENOSYS;
	}

	return (ret);
}

static int
linux_futex(struct thread *td, struct linux_futex_args *args)
{
	struct linux_pemuldata *pem;

	if (args->op & LINUX_FUTEX_PRIVATE_FLAG) {
		args->flags = 0;
		args->op &= ~LINUX_FUTEX_PRIVATE_FLAG;
	} else
		args->flags = FUTEX_SHARED;

	args->clockrt = args->op & LINUX_FUTEX_CLOCK_REALTIME;
	args->op = args->op & ~LINUX_FUTEX_CLOCK_REALTIME;

	/*
	 * Linux accepts FUTEX_CLOCK_REALTIME with FUTEX_WAIT since 5.14
	 * (the relative timeout is then measured against CLOCK_REALTIME).
	 */
	if (args->clockrt &&
	    args->op != LINUX_FUTEX_WAIT &&
	    args->op != LINUX_FUTEX_WAIT_BITSET &&
	    args->op != LINUX_FUTEX_WAIT_REQUEUE_PI &&
	    args->op != LINUX_FUTEX_LOCK_PI2)
		return (ENOSYS);

	switch (args->op) {
	case LINUX_FUTEX_WAIT:
		args->val3 = FUTEX_BITSET_MATCH_ANY;
		/* FALLTHROUGH */

	case LINUX_FUTEX_WAIT_BITSET:
		LINUX_CTR3(sys_futex, "WAIT uaddr %p val 0x%x bitset 0x%x",
		    args->uaddr, args->val, args->val3);

		return (linux_futex_op_wait(td, args));

	case LINUX_FUTEX_WAKE:
		args->val3 = FUTEX_BITSET_MATCH_ANY;
		/* FALLTHROUGH */

	case LINUX_FUTEX_WAKE_BITSET:
		LINUX_CTR3(sys_futex, "WAKE uaddr %p nrwake 0x%x bitset 0x%x",
		    args->uaddr, args->val, args->val3);

		return (linux_futex_op_wake(td, args));

	case LINUX_FUTEX_REQUEUE:
		/*
		 * Glibc does not use this operation since version 2.3.3,
		 * as it is racy and replaced by FUTEX_CMP_REQUEUE operation,
		 * but musl and other runtimes still do.  Linux implements it
		 * as FUTEX_CMP_REQUEUE without the value comparison, and so
		 * do we, for every brand.
		 */
		args->val3_compare = false;
		/* FALLTHROUGH */

	case LINUX_FUTEX_CMP_REQUEUE:
		LINUX_CTR5(sys_futex, "CMP_REQUEUE uaddr %p "
		    "nrwake 0x%x uval 0x%x uaddr2 %p nrequeue 0x%x",
		    args->uaddr, args->val, args->val3, args->uaddr2,
		    args->ts);

		return (linux_futex_op_requeue(td, args));

	case LINUX_FUTEX_WAKE_OP:
		LINUX_CTR5(sys_futex, "WAKE_OP "
		    "uaddr %p nrwake 0x%x uaddr2 %p op 0x%x nrwake2 0x%x",
		    args->uaddr, args->val, args->uaddr2, args->val3,
		    args->ts);

		return (linux_futex_wakeop(td, args));

	case LINUX_FUTEX_LOCK_PI:
		args->clockrt = true;
		/* FALLTHROUGH */

	case LINUX_FUTEX_LOCK_PI2:
		LINUX_CTR2(sys_futex, "LOCKPI uaddr %p val 0x%x",
		    args->uaddr, args->val);

		return (linux_futex_lock_pi(td, false, args));

	case LINUX_FUTEX_UNLOCK_PI:
		LINUX_CTR1(sys_futex, "UNLOCKPI uaddr %p",
		    args->uaddr);

		return (linux_futex_unlock_pi(td, false, args));

	case LINUX_FUTEX_TRYLOCK_PI:
		LINUX_CTR1(sys_futex, "TRYLOCKPI uaddr %p",
		    args->uaddr);

		return (linux_futex_lock_pi(td, true, args));

	/*
	 * Current implementation of FUTEX_WAIT_REQUEUE_PI and FUTEX_CMP_REQUEUE_PI
	 * can't be used anymore to implement conditional variables.
	 * A detailed explanation can be found here:
	 *
	 * https://sourceware.org/bugzilla/show_bug.cgi?id=13165
	 * and here http://austingroupbugs.net/view.php?id=609
	 *
	 * And since commit
	 * https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ed19993b5b0d05d62cc883571519a67dae481a14
	 * glibc does not use them.
	 */
	case LINUX_FUTEX_WAIT_REQUEUE_PI:
		/* not yet implemented */
		pem = pem_find(td->td_proc);
		if ((pem->flags & LINUX_XUNSUP_FUTEXPIOP) == 0) {
			linux_msg(td, "unsupported FUTEX_WAIT_REQUEUE_PI");
			pem->flags |= LINUX_XUNSUP_FUTEXPIOP;
		}
		return (ENOSYS);

	case LINUX_FUTEX_CMP_REQUEUE_PI:
		/* not yet implemented */
		pem = pem_find(td->td_proc);
		if ((pem->flags & LINUX_XUNSUP_FUTEXPIOP) == 0) {
			linux_msg(td, "unsupported FUTEX_CMP_REQUEUE_PI");
			pem->flags |= LINUX_XUNSUP_FUTEXPIOP;
		}
		return (ENOSYS);

	default:
		linux_msg(td, "unsupported futex op %d", args->op);
		return (ENOSYS);
	}
}

/*
 * pi protocol:
 * - 0 futex word value means unlocked.
 * - TID futex word value means locked.
 * Userspace uses atomic ops to lock/unlock these futexes without entering the
 * kernel. If the lock-acquire fastpath fails, (transition from 0 to TID fails),
 * then FUTEX_LOCK_PI is called.
 * The kernel atomically set FUTEX_WAITERS bit in the futex word value, if no
 * other waiters exists looks up the thread that owns the futex (it has put its
 * own TID into the futex value) and made this thread the owner of the internal
 * pi-aware lock object (mutex). Then the kernel tries to lock the internal lock
 * object, on which it blocks. Once it returns, it has the mutex acquired, and it
 * sets the futex value to its own TID and returns (futex value contains
 * FUTEX_WAITERS|TID).
 * The unlock fastpath would fail (because the FUTEX_WAITERS bit is set) and
 * FUTEX_UNLOCK_PI will be called.
 * If a futex is found to be held at exit time, the kernel sets the OWNER_DIED
 * bit of the futex word and wakes up the next futex waiter (if any), WAITERS
 * bit is preserved (if any).
 * If OWNER_DIED bit is set the kernel sanity checks the futex word value against
 * the internal futex state and if correct, acquire futex.
 */
static int
linux_futex_lock_pi(struct thread *td, bool try, struct linux_futex_args *args)
{
	struct umtx_abs_timeout timo;
	struct linux_emuldata *em;
	struct umtx_pi *pi, *new_pi;
	struct thread *td1;
	struct umtx_q *uq;
	int error, rv;
	uint32_t owner, old_owner;

	em = em_find(td);
	uq = td->td_umtxq;
	error = futex_key_get(args->uaddr, TYPE_PI_FUTEX, GET_SHARED(args),
	    &uq->uq_key);
	if (error != 0)
		return (error);
	if (args->ts != NULL)
		linux_umtx_abs_timeout_init(&timo, args);

	umtxq_lock(&uq->uq_key);
	pi = umtx_pi_lookup(&uq->uq_key);
	if (pi == NULL) {
		new_pi = umtx_pi_alloc(M_NOWAIT);
		if (new_pi == NULL) {
			umtxq_unlock(&uq->uq_key);
			new_pi = umtx_pi_alloc(M_WAITOK);
			umtxq_lock(&uq->uq_key);
			pi = umtx_pi_lookup(&uq->uq_key);
			if (pi != NULL) {
				umtx_pi_free(new_pi);
				new_pi = NULL;
			}
		}
		if (new_pi != NULL) {
			new_pi->pi_key = uq->uq_key;
			umtx_pi_insert(new_pi);
			pi = new_pi;
		}
	}
	umtx_pi_ref(pi);
	umtxq_unlock(&uq->uq_key);
	for (;;) {
		/* Try uncontested case first. */
		rv = casueword32(args->uaddr, FUTEX_UNOWNED, &owner, em->em_tid);
		/* The acquire succeeded. */
		if (rv == 0) {
			error = 0;
			break;
		}
		if (rv == -1) {
			error = EFAULT;
			break;
		}

		/*
		 * Nobody owns it, but the acquire failed. This can happen
		 * with ll/sc atomic.
		 */
		if (owner == FUTEX_UNOWNED) {
			error = thread_check_susp(td, true);
			if (error != 0)
				break;
			continue;
		}

		/*
		 * Avoid overwriting a possible error from sleep due
		 * to the pending signal with suspension check result.
		 */
		if (error == 0) {
			error = thread_check_susp(td, true);
			if (error != 0)
				break;
		}

		/* The futex word at *uaddr is already locked by the caller. */
		if ((owner & FUTEX_TID_MASK) == em->em_tid) {
			error = EDEADLK;
			break;
		}

		/*
		 * Futex owner died, handle_futex_death() set the OWNER_DIED bit
		 * and clear tid. Try to acquire it.
		 */
		if ((owner & FUTEX_TID_MASK) == FUTEX_UNOWNED) {
			old_owner = owner;
			owner = owner & (FUTEX_WAITERS | FUTEX_OWNER_DIED);
			owner |= em->em_tid;
			rv = casueword32(args->uaddr, old_owner, &owner, owner);
			if (rv == -1) {
				error = EFAULT;
				break;
			}
			if (rv == 1) {
				if (error == 0) {
					error = thread_check_susp(td, true);
					if (error != 0)
						break;
				}

				/*
				 * If this failed the lock could
				 * changed, restart.
				 */
				continue;
			}

			umtxq_lock(&uq->uq_key);
			umtxq_busy(&uq->uq_key);
			error = umtx_pi_claim(pi, td);
			umtxq_unbusy(&uq->uq_key);
			umtxq_unlock(&uq->uq_key);
			if (error != 0) {
				/*
				 * Since we're going to return an
				 * error, restore the futex to its
				 * previous, unowned state to avoid
				 * compounding the problem.
				 */
				(void)casuword32(args->uaddr, owner, old_owner);
			}
			break;
		}

		/*
		 * Inconsistent state: OWNER_DIED is set and tid is not 0.
		 * Linux does some checks of futex state, we return EINVAL,
		 * as the user space can take care of this.
		 */
		if ((owner & FUTEX_OWNER_DIED) != FUTEX_UNOWNED) {
			error = EINVAL;
			break;
		}

		if (try != 0) {
			error = EBUSY;
			break;
		}

		/*
		 * If we caught a signal, we have retried and now
		 * exit immediately.
		 */
		if (error != 0)
			break;

		umtxq_busy_unlocked(&uq->uq_key);

		/*
		 * Set the contested bit so that a release in user space knows
		 * to use the system call for unlock. If this fails either some
		 * one else has acquired the lock or it has been released.
		 */
		rv = casueword32(args->uaddr, owner, &owner,
		    owner | FUTEX_WAITERS);
		if (rv == -1) {
			umtxq_unbusy_unlocked(&uq->uq_key);
			error = EFAULT;
			break;
		}
		if (rv == 1) {
			umtxq_unbusy_unlocked(&uq->uq_key);
			error = thread_check_susp(td, true);
			if (error != 0)
				break;

			/*
			 * The lock changed and we need to retry or we
			 * lost a race to the thread unlocking the umtx.
			 */
			continue;
		}

		/*
		 * Substitute Linux thread id by native thread id to
		 * avoid refactoring code of umtxq_sleep_pi().
		 */
		td1 = linux_tdfind(td, owner & FUTEX_TID_MASK, -1);
		if (td1 != NULL) {
			owner = td1->td_tid;
			PROC_UNLOCK(td1->td_proc);
		} else {
			umtxq_unbusy_unlocked(&uq->uq_key);
			error = EINVAL;
			break;
		}

		umtxq_lock(&uq->uq_key);

		/* We set the contested bit, sleep. */
		error = umtxq_sleep_pi(uq, pi, owner, "futexp",
		    args->ts == NULL ? NULL : &timo,
		    (args->flags & FUTEX_SHARED) != 0);
		if (error != 0)
			continue;

		error = thread_check_susp(td, false);
		if (error != 0)
			break;
	}

	umtxq_lock(&uq->uq_key);
	umtx_pi_unref(pi);
	umtxq_unlock(&uq->uq_key);
	umtx_key_release(&uq->uq_key);
	return (error);
}

static int
linux_futex_unlock_pi(struct thread *td, bool rb, struct linux_futex_args *args)
{
	struct linux_emuldata *em;
	struct umtx_key key;
	uint32_t old, owner, new_owner;
	int count, error;

	em = em_find(td);

	/*
	 * Make sure we own this mtx.
	 */
	error = fueword32(args->uaddr, &owner);
	if (error == -1)
		return (EFAULT);
	if (!rb && (owner & FUTEX_TID_MASK) != em->em_tid)
		return (EPERM);

	error = futex_key_get(args->uaddr, TYPE_PI_FUTEX, GET_SHARED(args), &key);
	if (error != 0)
		return (error);
	umtxq_lock(&key);
	umtxq_busy(&key);
	error = umtx_pi_drop(td, &key, rb, &count);
	if (error != 0 || rb) {
		umtxq_unbusy(&key);
		umtxq_unlock(&key);
		umtx_key_release(&key);
		return (error);
	}
	umtxq_unlock(&key);

	/*
	 * When unlocking the futex, it must be marked as unowned if
	 * there is zero or one thread only waiting for it.
	 * Otherwise, it must be marked as contested.
	 */
	if (count > 1)
		new_owner = FUTEX_WAITERS;
	else
		new_owner = FUTEX_UNOWNED;

again:
	error = casueword32(args->uaddr, owner, &old, new_owner);
	if (error == 1) {
		error = thread_check_susp(td, false);
		if (error == 0)
			goto again;
	}
	umtxq_unbusy_unlocked(&key);
	umtx_key_release(&key);
	if (error == -1)
		return (EFAULT);
	if (error == 0 && old != owner)
		return (EINVAL);
	return (error);
}

static int
linux_futex_wakeop(struct thread *td, struct linux_futex_args *args)
{
	struct umtx_key key, key2;
	int nrwake, op_ret, ret;
	int error, count;

	if (args->uaddr == args->uaddr2)
		return (EINVAL);

	error = futex_key_get(args->uaddr, TYPE_FUTEX, GET_SHARED(args), &key);
	if (error != 0)
		return (error);
	error = futex_key_get(args->uaddr2, TYPE_FUTEX, GET_SHARED(args), &key2);
	if (error != 0) {
		umtx_key_release(&key);
		return (error);
	}
	umtxq_busy_unlocked(&key);
	error = futex_atomic_op(td, args->val3, args->uaddr2, &op_ret);
	linux_futex_lock2(&key, &key2);
	umtxq_unbusy(&key);
	if (error != 0)
		goto out;
	ret = umtxq_signal_mask(&key, args->val, args->val3);
	if (op_ret > 0) {
		nrwake = (int)(unsigned long)args->ts;
		count = umtxq_count(&key2);
		if (count > 0)
			ret += umtxq_signal_mask(&key2, nrwake, args->val3);
		else
			ret += umtxq_signal_mask(&key, nrwake, args->val3);
	}
	td->td_retval[0] = ret;
out:
	linux_futex_unlock2(&key, &key2);
	umtx_key_release(&key2);
	umtx_key_release(&key);
	return (error);
}

/*
 * Lock the sleep-queue chains of two futex keys.  Distinct addresses may
 * hash to the same chain, in which case the (non-recursive) chain mutex
 * must be taken only once; otherwise take both in address order so that
 * concurrent two-futex operations with swapped operands cannot deadlock.
 */
static void
linux_futex_lock2(struct umtx_key *key, struct umtx_key *key2)
{
	struct umtxq_chain *uc, *uc2;

	uc = umtxq_getchain(key);
	uc2 = umtxq_getchain(key2);
	if (uc == uc2) {
		mtx_lock(&uc->uc_lock);
	} else if ((uintptr_t)uc < (uintptr_t)uc2) {
		mtx_lock(&uc->uc_lock);
		mtx_lock(&uc2->uc_lock);
	} else {
		mtx_lock(&uc2->uc_lock);
		mtx_lock(&uc->uc_lock);
	}
}

static void
linux_futex_unlock2(struct umtx_key *key, struct umtx_key *key2)
{
	struct umtxq_chain *uc, *uc2;

	uc = umtxq_getchain(key);
	uc2 = umtxq_getchain(key2);
	mtx_unlock(&uc->uc_lock);
	if (uc != uc2)
		mtx_unlock(&uc2->uc_lock);
}

static int
linux_futex_op_requeue(struct thread *td, struct linux_futex_args *args)
{

	return (linux_futex_requeue_common(td, args->uaddr, GET_SHARED(args),
	    args->uaddr2, GET_SHARED(args), args->val,
	    (int)(unsigned long)args->ts, args->val3, args->val3_compare));
}

/*
 * Wake up to nrwake waiters of uaddr and move up to nrrequeue further
 * waiters to the sleep queue of uaddr2.  If compare is set, the futex word
 * at uaddr must still hold cmpval, otherwise EAGAIN is returned.  Returns
 * the number of woken plus requeued waiters, as Linux does for both
 * FUTEX_REQUEUE and FUTEX_CMP_REQUEUE.
 */
static int
linux_futex_requeue_common(struct thread *td, uint32_t *uaddr, int share,
    uint32_t *uaddr2, int share2, int nrwake, int nrrequeue, uint32_t cmpval,
    bool compare)
{
	struct umtx_key key, key2;
	int error, i, moved, ret;
	uint32_t uval;

	/*
	 * Linux allows this for non-PI futexes, we do not: the sleep
	 * queue cannot be requeued onto itself, and it is an incorrect
	 * usage of the declared ABI, so return EINVAL.
	 */
	if (uaddr == uaddr2)
		return (EINVAL);

	/*
	 * Sanity check to prevent signed integer overflow,
	 * see Linux CVE-2018-6927
	 */
	if (nrwake < 0 || nrrequeue < 0)
		return (EINVAL);

	error = futex_key_get(uaddr, TYPE_FUTEX, share, &key);
	if (error != 0)
		return (error);
	error = futex_key_get(uaddr2, TYPE_FUTEX, share2, &key2);
	if (error != 0) {
		umtx_key_release(&key);
		return (error);
	}
	umtxq_busy_unlocked(&key);
	error = fueword32(uaddr, &uval);
	if (error != 0)
		error = EFAULT;
	else if (compare && uval != cmpval)
		error = EWOULDBLOCK;
	linux_futex_lock2(&key, &key2);
	umtxq_unbusy(&key);
	moved = 0;
	if (error == 0) {
		/*
		 * umtxq_requeue() stops requeueing only once exactly
		 * nrrequeue waiters have been moved, so it cannot express
		 * "requeue none"; Linux wakes nrwake and moves nobody.
		 */
		if (nrrequeue == 0) {
			ret = nrwake == 0 ? 0 : umtxq_signal_mask(&key, nrwake,
			    FUTEX_BITSET_MATCH_ANY);
		} else {
			ret = umtxq_requeue(&key, nrwake, &key2, nrrequeue);
			moved = ret > nrwake ? ret - nrwake : 0;
			/*
			 * umtxq_requeue() overwrites each moved waiter's key
			 * with a copy of key2 without transferring the VM
			 * object references a shared key carries: the
			 * waiter later releases a reference on key2's object
			 * it never took, and its own reference on key's
			 * object is orphaned.  Balance both here; the
			 * waiters cannot run before the chains are unlocked.
			 */
			if (key2.shared) {
				for (i = 0; i < moved; i++)
					vm_object_reference(
					    key2.info.shared.object);
			}
		}
		td->td_retval[0] = ret;
	}
	linux_futex_unlock2(&key, &key2);
	if (key.shared) {
		for (i = 0; i < moved; i++)
			vm_object_deallocate(key.info.shared.object);
	}
	umtx_key_release(&key2);
	umtx_key_release(&key);
	return (error);
}

static int
linux_futex_op_wake(struct thread *td, struct linux_futex_args *args)
{
	struct umtx_key key;
	int error;

	if (args->val3 == 0)
		return (EINVAL);

	error = futex_key_get(args->uaddr, TYPE_FUTEX, GET_SHARED(args), &key);
	if (error != 0)
		return (error);
	umtxq_lock(&key);
	td->td_retval[0] = umtxq_signal_mask(&key, args->val, args->val3);
	umtxq_unlock(&key);
	umtx_key_release(&key);
	return (0);
}

static int
linux_futex_op_wait(struct thread *td, struct linux_futex_args *args)
{
	struct umtx_abs_timeout timo;
	struct umtx_q *uq;
	uint32_t uval;
	int error;

	if (args->val3 == 0)
		return (EINVAL);

	uq = td->td_umtxq;
	error = futex_key_get(args->uaddr, TYPE_FUTEX, GET_SHARED(args),
	    &uq->uq_key);
	if (error != 0)
		return (error);
	if (args->ts != NULL)
		linux_umtx_abs_timeout_init(&timo, args);
	umtxq_lock(&uq->uq_key);
	umtxq_busy(&uq->uq_key);
	uq->uq_bitset = args->val3;
	umtxq_insert(uq);
	umtxq_unlock(&uq->uq_key);
	error = fueword32(args->uaddr, &uval);
	if (error != 0)
		error = EFAULT;
	else if (uval != args->val)
		error = EWOULDBLOCK;
	umtxq_lock(&uq->uq_key);
	umtxq_unbusy(&uq->uq_key);
	if (error == 0) {
		error = umtxq_sleep(uq, "futex",
		    args->ts == NULL ? NULL : &timo);
		if ((uq->uq_flags & UQF_UMTXQ) == 0)
			error = 0;
		else
			umtxq_remove(uq);
	} else if ((uq->uq_flags & UQF_UMTXQ) != 0) {
		umtxq_remove(uq);
	}
	umtxq_unlock(&uq->uq_key);
	umtx_key_release(&uq->uq_key);
	/*
	 * Linux restarts an interrupted FUTEX_WAIT transparently when the
	 * handler has SA_RESTART (via restart_block for timed waits).  With
	 * no timeout, or an absolute one, the restart is exact here too; a
	 * relative timeout would be re-armed from scratch, so that case
	 * keeps EINTR.
	 */
	if (error == ERESTART && args->ts != NULL &&
	    args->op == LINUX_FUTEX_WAIT)
		error = EINTR;
	return (error);
}

static void
linux_umtx_abs_timeout_init(struct umtx_abs_timeout *timo,
    struct linux_futex_args *args)
{
	int clockid, absolute;

	/*
	 * The FUTEX_CLOCK_REALTIME option bit can be employed only with the
	 * FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_LOCK_PI2.
	 * For FUTEX_WAIT, timeout is interpreted as a relative value, for other
	 * futex operations timeout is interpreted as an absolute value.
	 * If FUTEX_CLOCK_REALTIME option bit is set, the Linux kernel measures
	 * the timeout against the CLOCK_REALTIME clock, otherwise the kernel
	 * measures the timeout against the CLOCK_MONOTONIC clock.
	 */
	clockid = args->clockrt ? CLOCK_REALTIME : CLOCK_MONOTONIC;
	absolute = args->op == LINUX_FUTEX_WAIT ? false : true;
	umtx_abs_timeout_init(timo, clockid, absolute, args->ts);

	/*
	 * An absolute deadline of exactly zero converts to an sbintime of
	 * zero, which msleep_sbt() takes as "no timeout".  It has expired
	 * on every clock, so make it expire rather than sleep forever.
	 */
	if (absolute && timo->end.tv_sec == 0 && timo->end.tv_nsec == 0)
		timo->end.tv_nsec = 1;
}

int
linux_sys_futex(struct thread *td, struct linux_sys_futex_args *args)
{
	struct linux_futex_args fargs = {
		.uaddr = args->uaddr,
		.op = args->op,
		.val = args->val,
		.ts = NULL,
		.uaddr2 = args->uaddr2,
		.val3 = args->val3,
		.val3_compare = true,
	};
	int error;

	switch (args->op & LINUX_FUTEX_CMD_MASK) {
	case LINUX_FUTEX_WAIT:
	case LINUX_FUTEX_WAIT_BITSET:
	case LINUX_FUTEX_LOCK_PI:
	case LINUX_FUTEX_LOCK_PI2:
		if (args->timeout != NULL) {
			error = linux_get_timespec(&fargs.kts, args->timeout);
			if (error != 0)
				return (error);
			fargs.ts = &fargs.kts;
		}
		break;
	default:
		fargs.ts = PTRIN(args->timeout);
	}
	return (linux_futex(td, &fargs));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_sys_futex_time64(struct thread *td,
    struct linux_sys_futex_time64_args *args)
{
	struct linux_futex_args fargs = {
		.uaddr = args->uaddr,
		.op = args->op,
		.val = args->val,
		.ts = NULL,
		.uaddr2 = args->uaddr2,
		.val3 = args->val3,
		.val3_compare = true,
	};
	int error;

	switch (args->op & LINUX_FUTEX_CMD_MASK) {
	case LINUX_FUTEX_WAIT:
	case LINUX_FUTEX_WAIT_BITSET:
	case LINUX_FUTEX_LOCK_PI:
	case LINUX_FUTEX_LOCK_PI2:
		if (args->timeout != NULL) {
			error = linux_get_timespec64(&fargs.kts, args->timeout);
			if (error != 0)
				return (error);
			fargs.ts = &fargs.kts;
		}
		break;
	default:
		fargs.ts = PTRIN(args->timeout);
	}
	return (linux_futex(td, &fargs));
}
#endif

/*
 * futex2 interface.
 *
 * Validate futex2 flags and derive the sleep-queue sharing mode.  Only
 * 32-bit futex words are supported, exactly as the legacy futex(2)
 * interface; smaller and 64-bit words are rejected with EINVAL like
 * Linux does.  NUMA-aware futexes (FUTEX2_NUMA, FUTEX2_MPOL) change the
 * futex word layout and are not implemented.
 */
static int
linux_futex2_share(uint32_t flags, int *share)
{

	if ((flags & ~LINUX_FUTEX2_VALID_MASK) != 0)
		return (EINVAL);
	if ((flags & LINUX_FUTEX2_SIZE_MASK) != LINUX_FUTEX2_SIZE_U32)
		return (EINVAL);
	if ((flags & (LINUX_FUTEX2_NUMA | LINUX_FUTEX2_MPOL)) != 0) {
		LINUX_RATELIMIT_MSG("unsupported futex2 NUMA/MPOL flags");
		return (EINVAL);
	}
	*share = (flags & LINUX_FUTEX2_PRIVATE) != 0 ? THREAD_SHARE :
	    AUTO_SHARE;
	return (0);
}

/*
 * futex2 timeouts are absolute and measured against clockid, which must
 * be CLOCK_MONOTONIC or CLOCK_REALTIME.  Linux validates the clock only
 * when a timeout is actually supplied.
 */
static int
linux_futex2_clock(l_int clockid, bool *clockrt)
{

	switch (clockid) {
	case LINUX_CLOCK_REALTIME:
		*clockrt = true;
		return (0);
	case LINUX_CLOCK_MONOTONIC:
		*clockrt = false;
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * futex_validate_input(): with 32-bit futex words the value and the mask
 * must fit in 32 bits, otherwise Linux returns EINVAL.
 */
static inline bool
linux_futex2_fits_u32(uint64_t v)
{

	return ((v >> 32) == 0);
}

int
linux_futex_wait(struct thread *td, struct linux_futex_wait_args *args)
{
	struct linux_futex_args fargs;
	int error, share;

	error = linux_futex2_share(args->flags, &share);
	if (error != 0)
		return (error);
	if (!linux_futex2_fits_u32(args->val) ||
	    !linux_futex2_fits_u32(args->mask))
		return (EINVAL);

	bzero(&fargs, sizeof(fargs));
	fargs.op = LINUX_FUTEX_WAIT_BITSET;
	fargs.uaddr = args->uaddr;
	fargs.flags = share == AUTO_SHARE ? FUTEX_SHARED : 0;
	fargs.val = args->val;
	fargs.val3 = args->mask;
	if (args->timeout != NULL) {
		error = linux_futex2_clock(args->clockid, &fargs.clockrt);
		if (error != 0)
			return (error);
		/* EFAULT on a bad pointer, EINVAL on an invalid timespec. */
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
		error = linux_get_timespec64(&fargs.kts, args->timeout);
#else
		error = linux_get_timespec(&fargs.kts, args->timeout);
#endif
		if (error != 0)
			return (error);
		fargs.ts = &fargs.kts;
	}

	LINUX_CTR3(sys_futex, "futex_wait uaddr %p val 0x%x mask 0x%x",
	    fargs.uaddr, fargs.val, fargs.val3);

	return (linux_futex_op_wait(td, &fargs));
}

int
linux_futex_wake(struct thread *td, struct linux_futex_wake_args *args)
{
	struct linux_futex_args fargs;
	struct umtx_key key;
	int error, share;

	error = linux_futex2_share(args->flags, &share);
	if (error != 0)
		return (error);
	if (!linux_futex2_fits_u32(args->mask))
		return (EINVAL);
	if (args->mask == 0)
		return (EINVAL);

	/*
	 * Unlike FUTEX_WAKE, which wakes one waiter for nr == 0, the
	 * futex2 interface is strict: nr <= 0 wakes nobody.  The address
	 * is still validated.
	 */
	if (args->nr <= 0) {
		error = futex_key_get(args->uaddr, TYPE_FUTEX, share, &key);
		if (error != 0)
			return (error);
		umtx_key_release(&key);
		td->td_retval[0] = 0;
		return (0);
	}

	bzero(&fargs, sizeof(fargs));
	fargs.op = LINUX_FUTEX_WAKE_BITSET;
	fargs.uaddr = args->uaddr;
	fargs.flags = share == AUTO_SHARE ? FUTEX_SHARED : 0;
	fargs.val = args->nr;
	fargs.val3 = args->mask;

	LINUX_CTR3(sys_futex, "futex_wake uaddr %p nr 0x%x mask 0x%x",
	    fargs.uaddr, fargs.val, fargs.val3);

	return (linux_futex_op_wake(td, &fargs));
}

/*
 * Copy in and validate a futex_waitv array (futex_parse_waitv()).
 */
static int
linux_futex2_parse_waitv(const struct l_futex_waitv *uwaiters,
    struct l_futex_waitv *waiters, u_int nr, int *share)
{
	u_int i;
	int error;

	error = copyin(uwaiters, waiters, nr * sizeof(*waiters));
	if (error != 0)
		return (EFAULT);
	for (i = 0; i < nr; i++) {
		if (waiters[i].__reserved != 0)
			return (EINVAL);
		error = linux_futex2_share(waiters[i].flags, &share[i]);
		if (error != 0)
			return (error);
		if (!linux_futex2_fits_u32(waiters[i].val))
			return (EINVAL);
		/* The address must be representable in this ABI. */
		if (waiters[i].uaddr != (uint64_t)(l_uintptr_t)waiters[i].uaddr)
			return (EFAULT);
	}
	return (0);
}

int
linux_futex_requeue(struct thread *td, struct linux_futex_requeue_args *args)
{
	struct l_futex_waitv waiters[2];
	int share[2];
	int error;

	if (args->flags != 0)
		return (EINVAL);
	if (args->waiters == NULL)
		return (EINVAL);
	error = linux_futex2_parse_waitv(args->waiters, waiters, nitems(waiters),
	    share);
	if (error != 0)
		return (error);

	LINUX_CTR5(sys_futex, "futex_requeue uaddr %p nrwake 0x%x "
	    "uval 0x%x uaddr2 %p nrequeue 0x%x",
	    PTRIN(waiters[0].uaddr), args->nr_wake, (uint32_t)waiters[0].val,
	    PTRIN(waiters[1].uaddr), args->nr_requeue);

	return (linux_futex_requeue_common(td, PTRIN(waiters[0].uaddr),
	    share[0], PTRIN(waiters[1].uaddr), share[1], args->nr_wake,
	    args->nr_requeue, (uint32_t)waiters[0].val, true));
}

int
linux_set_robust_list(struct thread *td, struct linux_set_robust_list_args *args)
{
	struct linux_emuldata *em;

	if (args->len != sizeof(struct linux_robust_list_head))
		return (EINVAL);

	em = em_find(td);
	em->robust_futexes = args->head;

	return (0);
}

int
linux_get_robust_list(struct thread *td, struct linux_get_robust_list_args *args)
{
	struct linux_emuldata *em;
	struct linux_robust_list_head *head;
	l_size_t len;
	struct thread *td2;
	int error;

	if (!args->pid) {
		em = em_find(td);
		KASSERT(em != NULL, ("get_robust_list: emuldata notfound.\n"));
		head = em->robust_futexes;
	} else {
		td2 = linux_tdfind(td, args->pid, -1);
		if (td2 == NULL)
			return (ESRCH);
		if (SV_PROC_ABI(td2->td_proc) != SV_ABI_LINUX) {
			PROC_UNLOCK(td2->td_proc);
			return (EPERM);
		}

		em = em_find(td2);
		KASSERT(em != NULL, ("get_robust_list: emuldata notfound.\n"));
		/* XXX: ptrace? */
		if (priv_check(td, PRIV_CRED_SETUID) ||
		    priv_check(td, PRIV_CRED_SETEUID) ||
		    p_candebug(td, td2->td_proc)) {
			PROC_UNLOCK(td2->td_proc);
			return (EPERM);
		}
		head = em->robust_futexes;

		PROC_UNLOCK(td2->td_proc);
	}

	len = sizeof(struct linux_robust_list_head);
	error = copyout(&len, args->len, sizeof(l_size_t));
	if (error != 0)
		return (EFAULT);

	return (copyout(&head, args->head, sizeof(l_uintptr_t)));
}

static int
handle_futex_death(struct thread *td, struct linux_emuldata *em, uint32_t *uaddr,
    unsigned int pi, bool pending_op)
{
	uint32_t uval, nval, mval;
	int error;

retry:
	error = fueword32(uaddr, &uval);
	if (error != 0)
		return (EFAULT);

	/*
	 * Special case for regular (non PI) futexes. The unlock path in
	 * user space has two race scenarios:
	 *
	 * 1. The unlock path releases the user space futex value and
	 *    before it can execute the futex() syscall to wake up
	 *    waiters it is killed.
	 *
	 * 2. A woken up waiter is killed before it can acquire the
	 *    futex in user space.
	 *
	 * In both cases the TID validation below prevents a wakeup of
	 * potential waiters which can cause these waiters to block
	 * forever.
	 *
	 * In both cases it is safe to attempt waking up a potential
	 * waiter without touching the user space futex value and trying
	 * to set the OWNER_DIED bit.
	 */
	if (pending_op && !pi && !uval) {
		(void)futex_wake(td, uaddr, 1, true);
		return (0);
	}

	if ((uval & FUTEX_TID_MASK) == em->em_tid) {
		mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
		error = casueword32(uaddr, uval, &nval, mval);
		if (error == -1)
			return (EFAULT);
		if (error == 1) {
			error = thread_check_susp(td, false);
			if (error != 0)
				return (error);
			goto retry;
		}

		if (!pi && (uval & FUTEX_WAITERS)) {
			error = futex_wake(td, uaddr, 1, true);
			if (error != 0)
				return (error);
		} else if (pi && (uval & FUTEX_WAITERS)) {
			error = futex_wake_pi(td, uaddr, true);
			if (error != 0)
				return (error);
		}
	}

	return (0);
}

static int
fetch_robust_entry(struct linux_robust_list **entry,
    struct linux_robust_list **head, unsigned int *pi)
{
	l_ulong uentry;
	int error;

	error = copyin((const void *)head, &uentry, sizeof(uentry));
	if (error != 0)
		return (EFAULT);

	*entry = (void *)(uentry & ~1UL);
	*pi = uentry & 1;

	return (0);
}

#define	LINUX_HANDLE_DEATH_PENDING	true
#define	LINUX_HANDLE_DEATH_LIST		false

/* This walks the list of robust futexes releasing them. */
void
release_futexes(struct thread *td, struct linux_emuldata *em)
{
	struct linux_robust_list_head *head;
	struct linux_robust_list *entry, *next_entry, *pending;
	unsigned int limit = 2048, pi, next_pi, pip;
	uint32_t *uaddr;
	l_long futex_offset;
	int error;

	head = em->robust_futexes;
	if (head == NULL)
		return;

	if (fetch_robust_entry(&entry, PTRIN(&head->list.next), &pi))
		return;

	error = copyin(&head->futex_offset, &futex_offset,
	    sizeof(futex_offset));
	if (error != 0)
		return;

	if (fetch_robust_entry(&pending, PTRIN(&head->pending_list), &pip))
		return;

	while (entry != &head->list) {
		error = fetch_robust_entry(&next_entry, PTRIN(&entry->next),
		    &next_pi);

		/*
		 * A pending lock might already be on the list, so
		 * don't process it twice.
		 */
		if (entry != pending) {
			uaddr = (uint32_t *)((caddr_t)entry + futex_offset);
			if (handle_futex_death(td, em, uaddr, pi,
			    LINUX_HANDLE_DEATH_LIST))
				return;
		}
		if (error != 0)
			return;

		entry = next_entry;
		pi = next_pi;

		if (!--limit)
			break;

		sched_relinquish(curthread);
	}

	if (pending) {
		uaddr = (uint32_t *)((caddr_t)pending + futex_offset);
		(void)handle_futex_death(td, em, uaddr, pip,
		    LINUX_HANDLE_DEATH_PENDING);
	}
}

/*
 * futex_waitv(2): wait on up to FUTEX_WAITV_MAX 32-bit futexes at once,
 * returning the index of the one that was woken.  Each entry gets its own
 * umtx queue entry; all of them share one wait channel (uq_wchan), so a
 * wake on any queue wakes the thread.  The check-and-queue pass is done
 * entry by entry under the respective chain's busy flag, exactly like a
 * single FUTEX_WAIT; a value mismatch unwinds (EAGAIN unless an already
 * queued entry was woken meanwhile, in which case that index is returned,
 * as on Linux).  The timeout is absolute against clockid.
 */
struct linux_waitv_state {
	struct umtx_q	*uq[LINUX_FUTEX_WAITV_MAX];
	bool		keyed[LINUX_FUTEX_WAITV_MAX];
	bool		queued[LINUX_FUTEX_WAITV_MAX];
};

/* Remove the entries still queued; return the lowest index that fired. */
static int
linux_waitv_unwind(struct linux_waitv_state *st, int n)
{
	struct umtx_q *uq;
	int i, fired;

	fired = -1;
	for (i = 0; i < n; i++) {
		uq = st->uq[i];
		if (st->queued[i]) {
			umtxq_lock(&uq->uq_key);
			if ((uq->uq_flags & UQF_UMTXQ) != 0)
				umtxq_remove(uq);
			else if (fired < 0)
				fired = i;
			umtxq_unlock(&uq->uq_key);
		}
		if (st->keyed[i])
			umtx_key_release(&uq->uq_key);
	}
	return (fired);
}

int
linux_futex_waitv(struct thread *td, struct linux_futex_waitv_args *args)
{
	struct linux_waitv_state *st;
	struct l_futex_waitv *wv;
	struct timespec ts, now;
	struct umtx_q *uq;
	sbintime_t sbt;
	uint32_t uval;
	int error, i, n, share, fired;
	bool clockrt, timed, slept;

	n = args->nr_futexes;
	if (n == 0 || n > LINUX_FUTEX_WAITV_MAX || args->flags != 0)
		return (EINVAL);
	timed = args->timeout != NULL;
	if (timed) {
		error = linux_futex2_clock(args->clockid, &clockrt);
		if (error != 0)
			return (error);
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
		error = linux_get_timespec64(&ts, args->timeout);
#else
		error = linux_get_timespec(&ts, args->timeout);
#endif
		if (error != 0)
			return (error);
		if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 || ts.tv_sec < 0)
			return (EINVAL);
	}
	wv = malloc(n * sizeof(*wv), M_LINUX, M_WAITOK);
	error = copyin(PTRIN(args->waiters), wv, n * sizeof(*wv));
	if (error != 0) {
		free(wv, M_LINUX);
		return (error);
	}
	for (i = 0; i < n; i++) {
		if (wv[i].__reserved != 0 || (wv[i].uaddr & 3) != 0 ||
		    wv[i].val > UINT32_MAX ||
		    linux_futex2_share(wv[i].flags, &share) != 0) {
			free(wv, M_LINUX);
			return (EINVAL);
		}
	}

	st = malloc(sizeof(*st), M_LINUX, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++) {
		uq = umtxq_alloc();
		uq->uq_thread = td;
		uq->uq_bitset = FUTEX_BITSET_MATCH_ANY;
		uq->uq_wchan = st;
		st->uq[i] = uq;
	}
	fired = -1;
	error = 0;
	slept = false;
	/* Check and queue each futex. */
	for (i = 0; i < n; i++) {
		uq = st->uq[i];
		(void)linux_futex2_share(wv[i].flags, &share);
		error = futex_key_get((void *)(uintptr_t)wv[i].uaddr, TYPE_FUTEX,
		    share, &uq->uq_key);
		if (error != 0)
			break;
		st->keyed[i] = true;
		umtxq_lock(&uq->uq_key);
		umtxq_busy(&uq->uq_key);
		umtxq_unlock(&uq->uq_key);
		error = fueword32((void *)(uintptr_t)wv[i].uaddr, &uval);
		umtxq_lock(&uq->uq_key);
		if (error != 0) {
			umtxq_unbusy(&uq->uq_key);
			umtxq_unlock(&uq->uq_key);
			error = EFAULT;
			break;
		}
		if (uval != (uint32_t)wv[i].val) {
			umtxq_unbusy(&uq->uq_key);
			umtxq_unlock(&uq->uq_key);
			error = EAGAIN;
			break;
		}
		umtxq_insert(uq);
		st->queued[i] = true;
		umtxq_unbusy(&uq->uq_key);
		umtxq_unlock(&uq->uq_key);
	}
	while (error == 0) {
		struct timespec rem;
		sigset_t pend;

		/*
		 * Sleep on the shared channel.  The sleepqueue chain lock
		 * orders our "already woken?" check against a waker's
		 * wakeup(): a removal done before the check is seen, one done
		 * after it wakes us from the sleepqueue.
		 */
		sleepq_lock(st);
		for (i = 0; i < n; i++)
			if ((st->uq[i]->uq_flags & UQF_UMTXQ) == 0)
				break;
		if (i < n) {
			sleepq_release(st);
			break;			/* an entry fired */
		}
		/*
		 * Check the deadline *before* sleepq_add: sleepq_add consumes
		 * td_sleepqueue and only an actual wait returns it, so a
		 * sleepq_add not followed by a wait would leave the thread
		 * unable to sleep again (panic on the next _sleep).
		 */
		if (timed) {
			/* Absolute deadline on clockid -> remaining time. */
			if (clockrt)
				nanotime(&now);
			else
				nanouptime(&now);
			rem = ts;
			timespecsub(&rem, &now, &rem);
			if (rem.tv_sec < 0) {
				sleepq_release(st);
				error = EWOULDBLOCK;
				break;
			}
			sbt = tstosbt(rem);
			sleepq_add(st, NULL, "futexv",
			    SLEEPQ_SLEEP | SLEEPQ_INTERRUPTIBLE, 0);
			sleepq_set_timeout_sbt(st, sbt, 0, 0);
			error = sleepq_timedwait_sig(st, 0);
		} else {
			sleepq_add(st, NULL, "futexv",
			    SLEEPQ_SLEEP | SLEEPQ_INTERRUPTIBLE, 0);
			error = sleepq_wait_sig(st, 0);
		}
		slept = true;
		if (error == 0 || error == EWOULDBLOCK)
			break;
		/*
		 * EINTR/ERESTART: a real pending signal ends the wait; a
		 * transient interrupt (e.g. the process being single-threaded
		 * for a sibling thread's creation) does not, so re-sleep with
		 * the entries still queued rather than tearing them down and
		 * racing the value on restart.
		 */
		PROC_LOCK(td->td_proc);
		pend = td->td_sigqueue.sq_signals;
		SIGSETOR(pend, td->td_proc->p_sigqueue.sq_signals);
		SIGSETNAND(pend, td->td_sigmask);
		PROC_UNLOCK(td->td_proc);
		if (!SIGISEMPTY(pend))
			break;
		error = 0;			/* retry */
	}
	fired = linux_waitv_unwind(st, n);
	for (i = 0; i < n; i++)
		umtxq_free(st->uq[i]);
	free(st, M_LINUX);
	free(wv, M_LINUX);
	if (fired >= 0) {
		td->td_retval[0] = fired;
		return (0);
	}
	/* EWOULDBLOCK from the sleep is the deadline; from a value check EAGAIN. */
	if (slept && error == EWOULDBLOCK)
		error = ETIMEDOUT;
	/* Absolute timeouts make a restart exact. */
	if (error == EINTR)
		error = ERESTART;
	return (error);
}
