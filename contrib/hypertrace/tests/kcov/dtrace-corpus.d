# D programs compiled to DOF for the kernel-source harness.  Each program is
# enabled through DTRACEIOC_ENABLE and its records are checked byte-exactly.
@trace_arg0
khx:mod:func:entry { trace(arg0); }
@pred_printf
khx:mod:func:entry /arg0 == 5/ { printf("%d %d\n", arg0, arg1); }
@agg_count
khx:mod:func:entry { @c[arg0] = count(); }
@begin_end
BEGIN { trace(1); } END { trace(2); }
@agg_multi
khx:mod:func:entry { @c = count(); @s = sum(arg0); @q = quantize(arg0); @m[arg1] = max(arg0); }
@printf_fmt
khx:mod:func:entry { printf("v=%d s=%s\n", arg0, "lit"); }
@spec
self int s;
khx:mod:func:entry { self->s = speculation(); speculate(self->s); trace(arg0); }
khx:mod:func:return /self->s/ { commit(self->s); self->s = 0; }
@exit_prog
khx:mod:func:entry { exit(3); }
@two_ecbs
khx:mod:func:entry { trace(arg0); }
khx:mod:func:return { trace(arg1); }
@glob_entry
khx:::entry { trace(arg0); }
@nomatch
nosuchprov:::entry { trace(arg0); }
@agg_args
khx:mod:func:entry { @l = lquantize(arg0, 0, 100, 10); @ll = llquantize(arg0, 10, 0, 6, 20); @w = quantize(arg0, arg1); }
@exit_end
khx:mod:func:entry { trace(arg0); exit(0); }
END { trace(99); }
# ---- DIF subroutines and variables, run in host and guest probe context ----
@d_str
khx:mod:func:entry { trace(strlen(stringof(arg0))); trace(stringof(arg0)); trace(stringof(arg0) == "hello"); trace(stringof(arg0) < "help"); }
@d_case
khx:mod:func:entry { trace(toupper(stringof(arg0))); trace(tolower(stringof(arg0))); }
@d_path
khx:mod:func:entry { trace(basename(stringof(arg0))); trace(dirname(stringof(arg0))); trace(cleanpath(stringof(arg1))); }
@d_search
khx:mod:func:entry { this->s = stringof(arg0); trace(strchr(this->s, 'b')); trace(strrchr(this->s, ',')); trace(strstr(this->s, ";c")); trace(index(this->s, ",")); trace(rindex(this->s, ",")); trace(index(this->s, ",", 2)); trace(rindex(this->s, ",", 2)); }
@d_substr
khx:mod:func:entry { trace(substr(stringof(arg0), 4)); trace(substr(stringof(arg0), 4, 5)); trace(substr(stringof(arg0), -3)); }
@d_strtok
khx:mod:func:entry { trace(strtok(stringof(arg0), ",;")); trace(strtok(NULL, ",;")); trace(strtok(NULL, ",;")); }
@d_join
khx:mod:func:entry { trace(strjoin(stringof(arg0), stringof(arg1))); }
@d_lltostr
khx:mod:func:entry { trace(lltostr(arg0)); trace(lltostr(arg1)); trace(lltostr(arg1, 16)); trace(lltostr(arg1, 2)); }
@d_strtoll
khx:mod:func:entry { trace(strtoll(stringof(arg0))); trace(strtoll(stringof(arg1), 16)); trace(strtoll(stringof(arg2))); }
@d_hton
khx:mod:func:entry { trace(htons(arg0)); trace(htonl(arg0)); trace(htonll(arg0)); trace(ntohs(arg0)); trace(ntohl(arg0)); trace(ntohll(arg0)); }
@d_inet
khx:mod:func:entry { trace(inet_ntop(28, (void *)arg1)); trace(inet_ntop(2, (void *)arg0)); trace(inet_ntoa6((void *)arg1)); }
@d_json
khx:mod:func:entry { trace(json(stringof(arg0), "k.n")); trace(json(stringof(arg0), "s")); trace(json(stringof(arg0), "a[1]")); }
@d_copyin
khx:mod:func:entry { trace(*(uint64_t *)copyin(arg0, 8)); trace(copyinstr(arg1)); trace(copyinstr(arg1, 3)); }
@d_copyinto
khx:mod:func:entry { this->p = alloca(8); copyinto(arg0, 8, this->p); trace(*(uint64_t *)this->p); }
@d_bcopy
khx:mod:func:entry { this->p = alloca(8); bcopy((void *)arg0, this->p, 8); trace(*(uint64_t *)this->p); }
@d_kload
khx:mod:func:entry { trace(*(uint8_t *)arg0); trace(*(uint16_t *)arg0); trace(*(uint32_t *)arg0); trace(*(uint64_t *)arg0); trace(*(int8_t *)(arg0 + 7)); }
@d_uload
khx:mod:func:entry { trace(*(userland uint8_t *)arg0); trace(*(userland uint16_t *)arg0); trace(*(userland uint32_t *)arg0); trace(*(userland uint64_t *)arg0); trace(*(userland int8_t *)(arg0 + 7)); }
@d_memstr
khx:mod:func:entry { trace(memstr((void *)arg0, ',', 7)); }
@d_rand
khx:mod:func:entry { trace(rand() != -1); trace(random() != 0 || 1); }
@d_vars
khx:mod:func:entry { trace(pid); trace(tid); trace(execname); trace(uid); trace(gid); trace(errno); trace(cpu); trace(ppid); trace(jid); trace(jailname); trace(vmname); }
@d_vars2
khx:mod:func:entry { trace(probeprov); trace(probemod); trace(probefunc); trace(probename); trace(epid); trace(id); trace(timestamp != 0); trace(walltimestamp != 0); trace(stackdepth); trace(caller); trace(curthread != 0); trace(vtimestamp >= 0); }
@d_uvars
khx:mod:func:entry { trace(ustackdepth); trace(ucaller); trace(uregs[11]); trace(execargs); }
@d_hvars
khx:mod:func:entry { trace(hpid); trace(htid); trace(hexecname); trace(huid); trace(hgid); trace(herrno); trace(hcpu); trace(hppid); trace(hjid); trace(hjailname); trace(hvmname); }
@d_hvars2
khx:mod:func:entry { trace(hprobeprov); trace(hprobemod); trace(hprobefunc); trace(hprobename); trace(hepid); trace(hprid); trace(htimestamp != 0); trace(hwalltimestamp != 0); trace(hstackdepth); trace(hcaller); trace(hcurthread != 0); trace(hvtimestamp >= 0); }
@d_hargs
khx:mod:func:entry { trace(arg5); trace(arg9); }
@d_hustack
khx:mod:func:entry { trace(hustackdepth); trace(hucaller); }
@d_hexecargs
khx:mod:func:entry { trace(hexecargs); }
@d_wall
khx:mod:func:entry { trace(walltimestamp); trace(timestamp); trace(vtimestamp); }
@d_ustack
khx:mod:func:entry { ustack(4); }
@d_kstack
khx:mod:func:entry { stack(4); }
@d_stack
khx:mod:func:entry { stack(4); ustack(4); }
@d_assoc
int g;
self int t;
khx:mod:func:entry { g = arg0; self->t = arg1; a[arg0, "k"] = arg1 + 1; this->x = a[arg0, "k"]; trace(g); trace(self->t); trace(this->x); trace(a[arg0 + 1, "k"]); a[arg0, "k"] = 0; }
@d_arith
khx:mod:func:entry { trace(arg0 + arg1); trace(arg0 - arg1); trace(arg0 * arg1); trace(arg0 / arg1); trace(arg0 % arg1); trace(arg0 & arg1); trace(arg0 | arg1); trace(arg0 ^ arg1); trace(arg0 << 2); trace(arg0 >> 1); trace(~arg0); trace((int64_t)arg0 < (int64_t)arg1); trace(arg0 > arg1 ? 1 : 2); trace(!arg0); trace(-((int64_t)arg1)); trace((int64_t)arg1 / -1); }
@d_div0
khx:mod:func:entry { trace(arg0 / arg1); }
@d_badload
khx:mod:func:entry { trace(*(uint64_t *)arg0); }
@d_badstr
khx:mod:func:entry { trace(stringof(arg0)); }
@d_badcopyin
khx:mod:func:entry { trace(copyinstr(arg0)); }
@d_search_err
khx:mod:func:entry { this->s = stringof(arg0); trace(strchr(this->s, 'b')); }
@err_capture
dtrace:::ERROR { trace(arg3); trace(arg4); trace(arg5); }
@f_strlen
khx:mod:func:entry { trace(strlen(stringof(arg0))); }
@f_toupper
khx:mod:func:entry { trace(toupper(stringof(arg0))); }
@f_tolower
khx:mod:func:entry { trace(tolower(stringof(arg0))); }
@f_basename
khx:mod:func:entry { trace(basename(stringof(arg0))); }
@f_dirname
khx:mod:func:entry { trace(dirname(stringof(arg0))); }
@f_cleanpath
khx:mod:func:entry { trace(cleanpath(stringof(arg0))); }
@f_strchr
khx:mod:func:entry { trace(strchr(stringof(arg0), 'x')); }
@f_strrchr
khx:mod:func:entry { trace(strrchr(stringof(arg0), 'x')); }
@f_strstr
khx:mod:func:entry { trace(strstr(stringof(arg0), "x")); }
@f_strstr2
khx:mod:func:entry { trace(strstr(stringof(arg1), stringof(arg0))); }
@f_index
khx:mod:func:entry { trace(index(stringof(arg0), "x")); }
@f_rindex
khx:mod:func:entry { trace(rindex(stringof(arg0), "x")); }
@f_rindex2
khx:mod:func:entry { trace(rindex(stringof(arg1), stringof(arg0))); }
@f_substr
khx:mod:func:entry { trace(substr(stringof(arg0), 1)); }
@f_strtok
khx:mod:func:entry { trace(strtok(stringof(arg0), ",")); }
@f_strtok2
khx:mod:func:entry { trace(strtok(stringof(arg1), stringof(arg0))); }
@f_strjoin
khx:mod:func:entry { trace(strjoin(stringof(arg0), "x")); }
@f_strjoin2
khx:mod:func:entry { trace(strjoin(stringof(arg1), stringof(arg0))); }
@f_strtoll
khx:mod:func:entry { trace(strtoll(stringof(arg0))); }
@f_json
khx:mod:func:entry { trace(json(stringof(arg0), "k")); }
@f_json2
khx:mod:func:entry { trace(json(stringof(arg1), stringof(arg0))); }
@f_inet4
khx:mod:func:entry { trace(inet_ntop(2, (void *)arg0)); }
@f_inet6
khx:mod:func:entry { trace(inet_ntop(28, (void *)arg0)); }
@f_ntoa
khx:mod:func:entry { trace(inet_ntoa((void *)arg0)); }
@f_ntoa6
khx:mod:func:entry { trace(inet_ntoa6((void *)arg0)); }
@f_memstr
khx:mod:func:entry { trace(memstr((void *)arg0, ',', 4)); }
@f_copyin
khx:mod:func:entry { trace(*(uint64_t *)copyin(arg0, 8)); }
@f_copyinstr
khx:mod:func:entry { trace(copyinstr(arg0, 4)); }
@f_copyinto
khx:mod:func:entry { this->p = alloca(8); copyinto(arg0, 8, this->p); trace(*(uint64_t *)this->p); }
@f_bcopy
khx:mod:func:entry { this->p = alloca(8); bcopy((void *)arg0, this->p, 8); trace(*(uint64_t *)this->p); }
@f_strcmp
khx:mod:func:entry { trace(stringof(arg0) == stringof(arg1)); }
@f_strcmp2
khx:mod:func:entry { trace(stringof(arg1) < stringof(arg0)); }
@f_ptinfo
khx:mod:func:entry { trace(ptinfo(arg0)); }
@e_search
khx:mod:func:entry { this->s = stringof(arg0); trace(rindex(this->s, "")); trace(index(this->s, "")); trace(strstr(this->s, "")); trace(rindex(this->s, "zz")); trace(index(this->s, ",", 100)); trace(rindex(this->s, ",", -1)); trace(index(this->s, ",", -5)); trace(rindex(this->s, ",", 100)); trace(index(this->s, "zz")); trace(rindex(this->s, "", 3)); trace(index(this->s, "", 3)); trace(strchr(this->s, 'z') == NULL); trace(strrchr(this->s, 'z') == NULL); trace(strstr(this->s, "zz") == NULL); }
@e_substr
khx:mod:func:entry { this->s = stringof(arg0); trace(substr(this->s, 100)); trace(substr(this->s, -100)); trace(substr(this->s, 2, -1)); trace(substr(this->s, 0, 0)); trace(substr(this->s, -100, 2)); trace(substr(this->s, 1, 1000)); trace(substr(this->s, -3, 2)); }
@e_strtok
khx:mod:func:entry { trace(strtok(NULL, ",") == NULL); trace(strtok(stringof(arg0), "") ); trace(strtok(NULL, ",") == NULL); trace(strtok(",,,", ",") == NULL); }
@e_path
khx:mod:func:entry { trace(basename("/")); trace(dirname("/")); trace(basename("noslash")); trace(dirname("noslash")); trace(basename("a/b//")); trace(dirname("a/b//")); trace(cleanpath("/../a/./")); trace(dirname("//a")); trace(basename("")); trace(dirname("")); trace(cleanpath("a/..")); trace(cleanpath("/a/b/../../..")); }
@e_case
khx:mod:func:entry { trace(toupper("")); trace(tolower("")); trace(toupper("a1-Z")); trace(tolower("A1-z")); }
@e_strtoll
khx:mod:func:entry { trace(strtoll("")); trace(strtoll("z", 36)); trace(strtoll("  +12")); trace(strtoll("-0x10", 16)); trace(strtoll("777", 8)); trace(strtoll("12abc")); trace(strtoll("99999999999999999999")); }
@e_strtoll_base
khx:mod:func:entry { trace(strtoll("1", arg0)); }
@e_lltostr
khx:mod:func:entry { trace(lltostr(0)); trace(lltostr(-1, 16)); trace(lltostr(0, 2)); trace(lltostr(-9223372036854775807 - 1)); trace(lltostr(255, 36)); }
@e_lltostr_base
khx:mod:func:entry { trace(lltostr(5, arg0)); }
@e_json
khx:mod:func:entry { this->s = stringof(arg0); trace(json(this->s, "missing") == NULL); trace(json(this->s, "a[9]") == NULL); trace(json("{bad", "k") == NULL); trace(json(this->s, "k")); trace(json(this->s, "a")); trace(json("[1,2]", "[0]")); trace(json("{\"t\":true,\"f\":false,\"n\":null}", "t")); trace(json("{\"x\":\"a\\\"b\"}", "x")); }
@e_join
khx:mod:func:entry { trace(strjoin("", "")); trace(strjoin(stringof(arg0), "")); }
@e_inet
khx:mod:func:entry { trace(inet_ntop(99, (void *)arg0)); }
@e_inet6
khx:mod:func:entry { trace(inet_ntop(28, (void *)arg0)); }
@e_memref
khx:mod:func:entry { this->m = memref((void *)arg0, 8); trace(this->m[1]); printm(8, this->m); }
@e_copyout destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 8); copyoutstr("dtrace!", arg0 + 16, 8); trace(*(userland uint64_t *)arg0); trace(copyinstr(arg0 + 16)); }
@e_copyout_bad destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 8); }
@e_copyoutstr_bad destructive
khx:mod:func:entry { copyoutstr("x", arg0, 8); }
@e_progeny
khx:mod:func:entry { trace(progenyof(1)); trace(progenyof(arg0)); }
@e_speculate
khx:mod:func:entry { this->sp = speculation(); trace(this->sp); }
@h_args vprog
khx:mod:func:entry { trace(arg0); trace(arg1); trace(execname); trace(pid); }
@h_stack vprog
khx:mod:func:entry { stack(3); trace(vtimestamp); trace(walltimestamp); }
@a_stop destructive
khx:mod:func:entry { stop(); trace(1); }
@a_raise destructive
khx:mod:func:entry { raise(9); trace(1); }
@a_chill destructive
khx:mod:func:entry { chill(1); trace(1); }
@a_panic destructive
khx:mod:func:entry { panic(); }
@a_bkpt destructive
khx:mod:func:entry { breakpoint(); }
@a_jstack
khx:mod:func:entry { jstack(); }
@a_sym
khx:mod:func:entry { sym(arg0); }
@a_mod
khx:mod:func:entry { mod(arg0); }
@a_usym
khx:mod:func:entry { usym(arg0); }
@a_umod
khx:mod:func:entry { umod(arg0); }
@a_uaddr
khx:mod:func:entry { uaddr(arg0); }
@a_immstack
khx:mod:func:entry { immstack(); }
@a_pimmstack vsrc
khx:mod:func:entry { immstack(); }
@v_udiv
khx:mod:func:entry { trace((uint64_t)arg0 / (uint64_t)arg1); trace((uint64_t)arg0 % (uint64_t)arg1); trace((int64_t)arg0 % (int64_t)arg1); }
@v_udiv0
khx:mod:func:entry { trace((uint64_t)arg0 / (uint64_t)arg1); }
@v_urem0
khx:mod:func:entry { trace((uint64_t)arg0 % (uint64_t)arg1); }
@v_srem0
khx:mod:func:entry { trace((int64_t)arg0 % (int64_t)arg1); }
@v_sload
khx:mod:func:entry { trace(*(int16_t *)arg0); trace(*(int32_t *)arg0); trace(*(userland int16_t *)arg1); trace(*(userland int32_t *)arg1); }
@v_rload
khx:mod:func:entry { this->b = (char *)alloca(8); bcopy((void *)arg0, this->b, 8); trace(*(int8_t *)this->b); trace(*(int16_t *)this->b); trace(*(int32_t *)this->b); trace(*(uint8_t *)this->b); trace(*(uint16_t *)this->b); trace(*(uint32_t *)this->b); trace(*(uint64_t *)this->b); }
@v_store
struct khxs { int a; short b; char c; long d; };
khx:mod:func:entry { this->p = (struct khxs *)alloca(sizeof (struct khxs)); this->p->a = 1; this->p->b = 2; this->p->c = 3; this->p->d = 4; trace(this->p->a); trace(this->p->b); trace(this->p->c); trace(this->p->d); }
@v_store_tag
khx:mod:func:entry { this->p = (long *)alloca(8); *this->p = arg0; trace(*this->p); }
@v_gstr
string gs;
khx:mod:func:entry { gs = stringof(arg0); trace(gs); }
@v_tstr
self string ts;
khx:mod:func:entry { self->ts = stringof(arg0); trace(self->ts); }
@v_taa
self int ta[int];
khx:mod:func:entry { self->ta[1] = 5; trace(self->ta[1]); trace(self->ta[2]); }
@v_taas
self string tas[int];
khx:mod:func:entry { self->tas[1] = stringof(arg0); trace(self->tas[1]); }
@v_gaas
string gas[int];
khx:mod:func:entry { gas[1] = stringof(arg0); trace(gas[1]); }
@d_gregs
khx:mod:func:entry { trace(regs[0]); trace(regs[1]); trace(regs[2]); trace(regs[3]); trace(regs[4]); trace(regs[5]); trace(regs[6]); trace(regs[7]); trace(regs[8]); trace(regs[9]); trace(regs[10]); trace(regs[11]); trace(regs[14]); trace(regs[15]); trace(regs[16]); trace(regs[17]); }
@d_gregs_x
khx:mod:func:entry { trace(regs[18]); trace(regs[19 + 7]); trace(regs[19 + 0]); trace(regs[19 + 5]); trace(regs[19 + 21]); trace(regs[19 + 14]); trace(regs[19 + 13]); trace(regs[19 + 4]); trace(regs[19 + 6]); trace(regs[19 + 3]); trace(regs[19 + 2]); trace(regs[19 + 1]); trace(regs[19 + 11]); trace(regs[19 + 10]); trace(regs[19 + 9]); trace(regs[19 + 8]); }
@d_greg12
khx:mod:func:entry { trace(regs[12]); }
@d_greg13
khx:mod:func:entry { trace(regs[13]); }
@d_greg46
khx:mod:func:entry { trace(regs[19 + 27]); }
@d_greg45
khx:mod:func:entry { trace(regs[19 + 26]); }
@d_greg11
khx:mod:func:entry { trace(regs[11]); }
@d_hostid
khx:mod:func:entry { trace(epid); trace(id); }
@d_hregs
khx:mod:func:entry { trace(regs[11]); trace(regs[19 + 7]); trace(uregs[11]); trace(arg7); trace(arg9); trace(arg6); }
@h_args9 vprog
khx:mod:func:entry { trace(arg7); trace(arg9); trace(arg3); }
@u_struct
struct khxs { int a; short b; char c; long d; };
khx:mod:func:entry { trace(*(userland struct khxs *)arg0); }
@k_struct
struct khxs { int a; short b; char c; long d; };
khx:mod:func:entry { trace(*(struct khxs *)arg0); }
@u_arr
typedef char c8_t[8];
khx:mod:func:entry { trace(*(userland c8_t *)arg0); }
@u_ustr
khx:mod:func:entry { trace(*(userland string *)arg0); }
@g_bcopy_dst
khx:mod:func:entry { this->p = alloca(8); bcopy(this->p, (void *)arg0, 8); trace(1); }
@g_copyinto_dst
khx:mod:func:entry { copyinto(arg1, 8, (void *)arg0); trace(1); }
@g_copyin_big
khx:mod:func:entry { trace(*(uint64_t *)copyin(arg0, arg1)); }
@g_copyinstr_big
khx:mod:func:entry { trace(copyinstr(arg0, arg1)); }
@g_const
khx:mod:func:entry { trace(strlen(stringof(0x123))); }
@g_memref_const
khx:mod:func:entry { this->m = memref((void *)0x123, 8); trace(this->m[1]); }
@g_memref_big
khx:mod:func:entry { this->m = memref((void *)arg0, arg1); trace(this->m[1]); }
@g_alloca_big
khx:mod:func:entry { this->p = alloca(arg0); trace(1); }
@g_strjoin_big
khx:mod:func:entry { trace(strjoin(strjoin(stringof(arg0), stringof(arg0)), stringof(arg0))); }
@g_lltostr_noscratch
khx:mod:func:entry { this->p = alloca(arg0); trace(lltostr(12345)); }
@v_dyn
khx:mod:func:entry { a[arg0] = arg1; }
@v_tdyn
self int tx;
khx:mod:func:entry { self->tx = arg0; }
@v_size1
int64_t gx;
khx:mod:func:entry { gx = 1; }
@v_size2
int gx;
khx:mod:func:entry { gx = 1; }
@p_long
khxlong:::entry { trace(1); }
@a_immstack_tick
khx:mod::tick { immstack(); }
@l_mtx
khx:mod:func:entry { trace(mutex_owned((void *)arg0)); trace((uintptr_t)mutex_owner((void *)arg0)); trace(mutex_type_adaptive((void *)arg0)); trace(mutex_type_spin((void *)arg0)); }
@l_rd
khx:mod:func:entry { trace(rw_read_held((void *)arg0)); trace(sx_shared_held((void *)arg0)); }
@l_wr
khx:mod:func:entry { trace(rw_write_held((void *)arg0)); trace(rw_iswriter((void *)arg0)); trace(sx_exclusive_held((void *)arg0)); trace(sx_isexclusive((void *)arg0)); }
@s_strtoll
khx:mod:func:entry { trace(strtoll(stringof(arg0))); }
@s_strtoll16
khx:mod:func:entry { trace(strtoll(stringof(arg0), 16)); }
@m_probe
khxmod:khxmod:f:n { trace(1); }
@e_strtoll_hex
khx:mod:func:entry { trace(strtoll(stringof(arg0), 16)); }
@n_copyinstr
khx:mod:func:entry { trace(alloca(arg2) != NULL ? copyinstr(arg0) : ""); }
@n_strtok
khx:mod:func:entry { this->scr = alloca(arg2); trace(strtok(stringof(arg0), ",")); }
@n_substr
khx:mod:func:entry { this->scr = alloca(arg2); trace(substr(stringof(arg0), 1)); }
@n_json
khx:mod:func:entry { this->scr = alloca(arg2); trace(json(stringof(arg0), "k")); }
@n_toupper
khx:mod:func:entry { this->scr = alloca(arg2); trace(toupper(stringof(arg0))); }
@n_lltostr
khx:mod:func:entry { trace(alloca(arg2) != NULL ? lltostr(arg0) : ""); }
@n_basename
khx:mod:func:entry { this->scr = alloca(arg2); trace(basename(stringof(arg0))); }
@n_cleanpath
khx:mod:func:entry { this->scr = alloca(arg2); trace(cleanpath(stringof(arg0))); }
@n_inet4
khx:mod:func:entry { this->scr = alloca(arg2); trace(inet_ntop(2, (void *)arg0)); }
@n_inet6
khx:mod:func:entry { this->scr = alloca(arg2); trace(inet_ntop(28, (void *)arg0)); }
@n_memref
khx:mod:func:entry { this->scr = alloca(arg2); this->m = memref((void *)arg0, 8); trace(this->m[1]); }
@n_strjoin
khx:mod:func:entry { this->scr = alloca(arg2); trace(strjoin(stringof(arg0), "x")); }
@n_memstr
khx:mod:func:entry { this->scr = alloca(arg2); trace(memstr((void *)arg0, ',', 4)); }
@n_copyin
khx:mod:func:entry { this->scr = alloca(arg2); trace(*(uint64_t *)copyin(arg0, 8)); }
@n_execname
khx:mod:func:entry { this->scr = alloca(arg2); trace(execname); }
@n_jailname
khx:mod:func:entry { this->scr = alloca(arg2); trace(jailname); }
@n_execargs
khx:mod:func:entry { this->scr = alloca(arg2); trace(execargs); }
@n_ntoa6
khx:mod:func:entry { this->scr = alloca(arg2); trace(inet_ntoa6((void *)arg0)); }
@n_ntoa
khx:mod:func:entry { this->scr = alloca(arg2); trace(inet_ntoa((void *)arg0)); }
@zz_tok
khx:mod:func:entry { trace(strtok(stringof(arg0), ",")); }
@zz_sub
khx:mod:func:entry { trace(substr(stringof(arg0), 1)); }
@zz_up
khx:mod:func:entry { trace(toupper(stringof(arg0))); }
@zz_base
khx:mod:func:entry { trace(basename(stringof(arg0))); }
@zz_clean
khx:mod:func:entry { trace(cleanpath(stringof(arg0))); }
@zz_cpi
khx:mod:func:entry { trace(copyinstr(arg0)); }
@zz_json
khx:mod:func:entry { trace(json(stringof(arg0), "k")); }
@e_search_empty
khx:mod:func:entry { this->s = stringof(arg0); trace(rindex(this->s, "")); trace(index(this->s, "")); trace(strstr(this->s, "") == this->s); trace(rindex(this->s, "", -1)); trace(index(this->s, "", 100)); trace(rindex(this->s, "x", -1)); this->t = stringof(arg1); trace(rindex(this->t, "", -1)); trace(index(this->t, "", 100)); }
@e_substr2
khx:mod:func:entry { this->s = stringof(arg0); trace(substr(this->s, 2, -100)); trace(substr(this->s, 0, 1000)); }
@e_inet_af
khx:mod:func:entry { trace(inet_ntop(arg1, (void *)arg0)); }
@c_cmp
khx:mod:func:entry { this->a = (int64_t)arg0; this->b = (int64_t)arg1; trace(this->a < this->b); trace(this->a <= this->b); trace(this->a > this->b); trace(this->a >= this->b); trace(this->a == this->b); trace(this->a != this->b); trace((uint64_t)arg0 < (uint64_t)arg1); trace((uint64_t)arg0 <= (uint64_t)arg1); trace((uint64_t)arg0 > (uint64_t)arg1); trace((uint64_t)arg0 >= (uint64_t)arg1); }
@w_ldts
self int nv;
khx:mod:func:entry { trace(self->nv); }
@w_gnull
string gsn;
khx:mod:func:entry { gsn = stringof(arg1); trace(gsn == NULL); }
@w_lnull
khx:mod:func:entry { this->ls = stringof(arg1); trace(this->ls == NULL); }
@w_stts
self int sx;
khx:mod:func:entry { self->sx = arg0; trace(self->sx); }
@w_stls
khx:mod:func:entry { this->lx = arg0; trace(this->lx); }
@w_stgaa
int ga[int];
khx:mod:func:entry { ga[1] = arg0; trace(ga[1]); }
@w_sttaa
self int ta2[int];
khx:mod:func:entry { self->ta2[1] = arg0; trace(self->ta2[1]); }
@w_stgs
int gx2;
khx:mod:func:entry { gx2 = arg0; trace(gx2); }
@w_stb
khx:mod:func:entry { this->p = (char *)alloca(16); *(char *)this->p = arg0; trace(1); }
@w_sth
khx:mod:func:entry { this->p = (char *)alloca(16); *(short *)this->p = arg0; trace(1); }
@w_stw
khx:mod:func:entry { this->p = (char *)alloca(16); *(int *)this->p = arg0; trace(1); }
@w_stbg
khx:mod:func:entry { *(char *)arg0 = 1; trace(1); }
@w_align2
khx:mod:func:entry { this->p = (char *)alloca(16); *(short *)(this->p + 1) = 1; trace(1); }
@w_align4
khx:mod:func:entry { this->p = (char *)alloca(16); *(int *)(this->p + 2) = 1; trace(1); }
@w_align8
khx:mod:func:entry { this->p = (char *)alloca(16); *(long *)(this->p + 4) = 1; trace(1); }
@w_sthg
khx:mod:func:entry { *(short *)arg0 = 1; trace(1); }
@w_stwg
khx:mod:func:entry { *(int *)arg0 = 1; trace(1); }
@w_stxg
khx:mod:func:entry { *(long *)arg0 = 1; trace(1); }
@w_pred
khx:mod:func:entry /arg0 == 1/ { trace(2); }
@w_predc
khx:mod:func:entry /pid == 1/ { trace(3); }
@w_zone
khx:mod:func:entry { trace(zonename); }
@w_copys
struct khxs { int a; short b; char c; long d; };
khx:mod:func:entry { this->s = *(struct khxs *)arg0; trace(this->s.a); }
@ga_args
khxga:::entry { trace(arg6); trace(arg9); }
@w_unknownvar
khx:mod:func:entry { trace(epid); }
@w_vars_p0
khx:mod:func:entry { trace(ppid); trace(execargs == NULL); }
@w_gstrkey
khx:mod:func:entry { sk[stringof(arg0)] = 1; trace(sk[stringof(arg0)]); }
@p_bcopy0
khx:mod:func:entry { this->p = alloca(8); bcopy((void *)arg0, this->p, 0); trace(1); }
@p_overlap
khx:mod:func:entry { this->p = (char *)alloca(16); *(uint64_t *)this->p = 0x0807060504030201; bcopy(this->p, this->p + 4, 8); trace(*(uint64_t *)(this->p + 8)); }
@e_copyout0 destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 0); trace(1); }
@d_ucaller
khx:mod:func:entry { trace(ucaller); }
@d_ustackdepth
khx:mod:func:entry { trace(ustackdepth); }
@d_ustack1
khx:mod:func:entry { ustack(1); }
@g_constload
khx:mod:func:entry { trace(*(uint64_t *)0x123); }
@g_load16
khx:mod:func:entry { trace(*(uint16_t *)arg0); }
@n_tstr
self string nts;
khx:mod:func:entry { this->scr = alloca(arg2); self->nts = stringof(arg0); trace(1); }
@j_arr0
khx:mod:func:entry { trace(json(stringof(arg0), "a[0]")); }
@pm_forge
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = arg1; this->m[1] = 8; printm(8, this->m); }
@f_tracestr
khx:mod:func:entry { trace(stringof(arg0)); }
@e_execargs
khx:mod:func:entry { trace(execargs); }
@pm_forge_c
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = 0x123; this->m[1] = 8; printm(8, this->m); }
@r_craft
khx:mod:func:entry { trace(arg0 + arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8 + arg9); }
@big_kstack
khx:mod:func:entry { stack(200); }
@big_ustack
khx:mod:func:entry { ustack(3000); }
@e_copyin0
khx:mod:func:entry { this->p = copyin(arg0, 0); trace(1); }
@e_copyout_src destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 8); trace(1); }
@w_gstrkey_del
khx:mod:func:entry { sk2[stringof(arg0)] = 1; sk2[stringof(arg0)] = 0; trace(1); }
@w_tstr_only
self string tso;
khx:mod:func:entry { self->tso = stringof(arg0); trace(1); }
@w_gaas_only
string gso[int];
khx:mod:func:entry { gso[1] = stringof(arg0); trace(1); }
@a_pimmstack_n vsrc
khx:mod:func:entry { immstack(5); }
@big_stack_opt
khx:mod:func:entry { stack(); }
@big_ustack_str
khx:mod:func:entry { ustack(5, 3000000000); }
@w_fill
self string tfill;
string gfill[int];
khx:mod:func:entry { gfill[arg1] = stringof(arg0); self->tfill = stringof(arg0); }
@v_tsize1
self int64_t tsz;
khx:mod:func:entry { self->tsz = 1; }
@v_tsize2
self int tsz;
khx:mod:func:entry { self->tsz = 1; }
@v_asize1
int64_t asz[int];
khx:mod:func:entry { asz[1] = 1; }
@v_asize2
int asz[int];
khx:mod:func:entry { asz[1] = 1; }
@v_lsize1
this int64_t lsz;
khx:mod:func:entry { this->lsz = 1; }
@v_lsize2
this int lsz;
khx:mod:func:entry { this->lsz = 1; }
@p_nm
khxnm::: { trace(1); }
@p_def
khxdef::: { trace(1); }
@hlp_sym
dtrace:helper:ustack: /arg0 != 1/ { "khx`help"; }
@hlp_nomatch
dtrace:helper:ustack: /arg0 == 1/ { "never"; }
@d_ustack_str
khx:mod:func:entry { ustack(3, 64); }
@p_longprov
*:zm:zf:zn { trace(1); }
@w_gstructkey
struct khxs { int a; int b; }; khx:mod:func:entry { gk[*(struct khxs *)arg0] = 1; trace(1); }
@d_hcaller
khx:mod::entry { trace(hcaller != 0); }
@b_uload8
khx:mod:func:entry { trace(*(userland uint64_t *)arg0); }
@b_copyin8
khx:mod:func:entry { trace(*(uint64_t *)copyin(arg0, 8)); }
@b_copyin5
khx:mod:func:entry { this->p = (uint8_t *)copyin(arg0, 5); trace(this->p[4]); }
@b_copyout5 destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 5); trace(1); }
@b_copyout_kdst destructive
khx:mod:func:entry { copyout((void *)arg1, 0x1000, 8); trace(1); }
@b_copyout_lit destructive
khx:mod:func:entry { copyout("abcdefg", arg0, 8); trace(1); }
@b_copyout_tox destructive
khx:mod:func:entry { copyout((void *)0x10, arg0, 8); trace(1); }
@b_copyoutstr_t destructive
khx:mod:func:entry { copyoutstr(stringof((char *)arg1), arg0, 8); trace(1); }
@b_copyoutstr_tox destructive
khx:mod:func:entry { copyoutstr(stringof((char *)0x10), arg0, 8); trace(1); }
@b_execname
khx:mod:func:entry { trace(execname); }
@b_regs
khx:mod:func:entry { trace(regs[0]); }
@b_json
khx:mod:func:entry { trace(json("{\"a\":true,\"b\":false,\"c\":null,\"d\":5}", "a")); trace(json("{\"a\":true,\"b\":false,\"c\":null,\"d\":5}", "b")); trace(json("{\"a\":true,\"b\":false,\"c\":null,\"d\":5}", "c")); trace(json("{\"a\":true,\"b\":false,\"c\":null,\"d\":5}", "d")); }
@b_l_owner
khx:mod:func:entry { trace((uintptr_t)mutex_owner((void *)arg0)); }
@b_l_adaptive
khx:mod:func:entry { trace(mutex_type_adaptive((void *)arg0)); }
@b_l_spin
khx:mod:func:entry { trace(mutex_type_spin((void *)arg0)); }
@b_l_iswriter
khx:mod:func:entry { trace(rw_iswriter((void *)arg0)); }
@b_l_sxshared
khx:mod:func:entry { trace(sx_shared_held((void *)arg0)); }
@b_l_sxexcl
khx:mod:func:entry { trace(sx_exclusive_held((void *)arg0)); }
@b_l_sxisexcl
khx:mod:func:entry { trace(sx_isexclusive((void *)arg0)); }
@b_substr_neg
khx:mod:func:entry { trace(substr("abc", -5, 0)); }
@b_strchr
khx:mod:func:entry { trace(strchr(stringof(arg0), 'z')); }
@b_cleanpath
khx:mod:func:entry { trace(cleanpath(stringof(arg0))); }
@b_memref_scr
khx:mod:func:entry { this->a = alloca(8); this->m = memref(this->a, arg0); trace(this->m[1]); }
@b_memref_above
khx:mod:func:entry { this->a = (char *)alloca(8); this->m = memref(this->a + 64, 8); trace(this->m[1]); }
@b_memref_zero
khx:mod:func:entry { this->m = memref((void *)arg0, 0); trace(this->m[1]); }
@b_pm_const
khx:mod:func:entry { printm(8, (uintptr_t *)0x1000); }
@b_pm_above
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = (uintptr_t)this->m; this->m[1] = 8; printm(8, this->m + 8); }
@b_pm_short
khx:mod:func:entry { this->m = (uintptr_t *)alloca(8); this->m[0] = (uintptr_t)this->m; printm(8, this->m); }
@b_pm_big
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = (uintptr_t)this->m; this->m[1] = 16; printm(8, this->m); }
@b_pm_far
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = (uintptr_t)this->m + 4096; this->m[1] = 8; printm(8, this->m); }
@b_pm_tail
khx:mod:func:entry { this->m = (uintptr_t *)alloca(16); this->m[0] = (uintptr_t)this->m + 12; this->m[1] = 8; printm(8, this->m); }
@b_gs_bad
string gsbad;
khx:mod:func:entry { gsbad = stringof(arg0); trace(1); }
@b_ts_bad
self string tsbad;
khx:mod:func:entry { self->tsbad = stringof(arg0); trace(1); }
@b_alloca_huge
khx:mod:func:entry { this->p = alloca(arg0); trace(1); }
@b_pred
self int never;
khx:mod:func:entry /self->never/ { trace(1); }
@b_stmt_str
khx:mod:func:entry { this->s = "abc"; trace(1); }
@b_immstack3
khx:mod:func:entry { immstack(3); }
@b_hcaller_host
khx:mod::tick { trace(caller); }
@b_vflag1
int vfl;
khx:mod:func:entry { vfl = 1; }
@b_vflag2
string vfl;
khx:mod:func:entry { vfl = "x"; }
@b_basename_huge
khx:mod:func:entry { trace(strlen(basename("a/b"))); }
@b_cleanpath_huge
khx:mod:func:entry { trace(strlen(cleanpath("a/b"))); }
@b_stack0
khx:mod:func:entry { stack(); }
@b_ustack0
khx:mod:func:entry { ustack(); }
@b_strtoll
khx:mod:func:entry { trace(strtoll("\t 7")); trace(strtoll("0X1f", 16)); trace(strtoll("1f", 16)); trace(strtoll("0", 16)); trace(strtoll("012", 16)); }
@b_copyin16
khx:mod:func:entry { this->p = (uint64_t *)copyin(arg0, 16); trace(this->p[1]); }
@b_copyout16 destructive
khx:mod:func:entry { copyout((void *)arg1, arg0, 16); trace(1); }
@b_gs_copy
string gcp;
khx:mod:func:entry { gcp = stringof(arg0); trace(1); }
@b_fill_host
string gfill[uint64_t];
khx:mod:func:entry { gfill[arg1] = stringof(arg0); }
@b_strjoin_fit
khx:mod:func:entry { trace(strjoin("ab", "c")); }
@h_e2e vprog
khx:mod:func:entry { trace(1); trace(2); printf("x %d", 3); }
@h_e2e_host
khx:mod:func:entry { trace(1); trace(2); printf("x %d", 3); }
@h_e2e_pred vprog
int e2ecnt;
khx:mod:func:entry /++e2ecnt > 0/ { trace(e2ecnt); }
@h_e2e_pred_host
int e2ecnt;
khx:mod:func:entry /++e2ecnt > 0/ { trace(e2ecnt); }
@b_json_bare
khx:mod:func:entry { trace(json("{\"e\":nope}", "e")); }
@b_zero_str
self string zs;
khx:mod:func:entry { self->zs = stringof(arg0); self->zs = 0; trace(1); }
@b_casts
khx:mod:func:entry { trace(-1); trace(1u); trace(sizeof (int)); trace((char)300); trace((int)arg0 - 1); }
