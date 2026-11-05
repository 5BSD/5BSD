# Phase 5: other real-hardware items touched by this work.
#  audio (sndstat, 1 s tone on the default unit, mic level), uvideo camera
#  (/dev/video0 + one frame), Bluetooth (ng_ubt + HCI), dock Ethernet (ure0
#  link), the OTel rc services with a file target (started with onestart,
#  stopped again; no rc.conf or otel.conf edits), and podman port publishing
#  through OpenBSD PF (only with the 5BSD containernetworking-plugins).
# No vmm needed. Set HT_AUDIO_PLAY=no to skip the audible tone,
# HT_BT_INQUIRY=yes for a 10 s Bluetooth inquiry.

phase_begin devices
need_root
HT_ALLOW_GENERATION=${HT_ALLOW_GENERATION:-$(host_generation)}
need_generation
dry && dry_end
O=$HT_OUT
B=$HT_KIT/bin
sha256 -q /etc/rc.conf /etc/otel.conf /etc/pf.conf 2>/dev/null > "$O/config-before.sha256"

# --- audio ---------------------------------------------------------------------
cat /dev/sndstat > "$O/sndstat.txt" 2>&1
if grep -q '^pcm[0-9]' "$O/sndstat.txt"; then
	check audio-sndstat PASS "$(grep -c '^pcm' "$O/sndstat.txt") pcm devices; default $(sysctl -n hw.snd.default_unit)"
	mixer > "$O/mixer.txt" 2>&1
	if [ "${HT_AUDIO_PLAY:-yes}" = yes ]; then
		echo ">>> playing a 1 s 440 Hz tone on /dev/dsp (default unit)" | tee -a "$HT_LOG"
		"$B/ht-audio" play /dev/dsp 1 > "$O/audio-play.txt" 2>&1 &&
		    check audio-playback PASS "$(tail -1 "$O/audio-play.txt") (listen for the tone)" ||
		    check audio-playback FAIL "$(tail -1 "$O/audio-play.txt")"
	else
		check audio-playback SKIP "HT_AUDIO_PLAY=no"
	fi
	if grep -q 'rec' "$O/sndstat.txt"; then
		"$B/ht-audio" rec /dev/dsp 2 > "$O/audio-rec.txt" 2>&1
		pk=$(sed -n 's/.*PEAK \([-0-9.]*\) dBFS.*/\1/p' "$O/audio-rec.txt")
		if [ -n "$pk" ] && [ "$(echo "$pk > -90" | bc)" = 1 ]; then
			check audio-mic-level PASS "$(tail -1 "$O/audio-rec.txt")"
		else
			check audio-mic-level FAIL "$(tail -1 "$O/audio-rec.txt") (muted mic or no capture channel)"
		fi
	else
		check audio-mic-level SKIP "no recording channel in sndstat"
	fi
else
	check audio-sndstat FAIL "no pcm devices in /dev/sndstat"
fi

# --- camera (uvideo -> video(4)) ------------------------------------------------
usbconfig > "$O/usbconfig.txt" 2>&1
if [ -c /dev/video0 ]; then
	"$B/ht-camera" /dev/video0 "$O/frame.raw" > "$O/camera.txt" 2>&1 &&
	    check camera-frame PASS "$(tr '\n' ' ' < "$O/camera.txt" | cut -c1-200)" ||
	    check camera-frame FAIL "$(tail -1 "$O/camera.txt")"
else
	kldstat -q -n uvideo.ko && check camera-frame FAIL "uvideo loaded but no /dev/video0" ||
	    check camera-frame SKIP "no /dev/video0 (uvideo.ko not loaded; the kit does not load modules)"
fi

# --- Bluetooth --------------------------------------------------------------------
ngctl list > "$O/ngctl.txt" 2>&1
if grep -q 'Name: ubt0 ' "$O/ngctl.txt"; then
	check bt-ng-ubt PASS
	hccontrol -n ubt0hci read_bd_addr > "$O/bt.txt" 2>&1 &&
	    hccontrol -n ubt0hci read_local_version_information >> "$O/bt.txt" 2>&1 &&
	    check bt-hci PASS "$(grep -i 'BD_ADDR' "$O/bt.txt")" || check bt-hci FAIL "$(tail -1 "$O/bt.txt")"
	if [ "${HT_BT_INQUIRY:-no}" = yes ]; then
		hccontrol -n ubt0hci inquiry > "$O/bt-inquiry.txt" 2>&1
		check bt-inquiry INFO "$(grep -c 'BD_ADDR' "$O/bt-inquiry.txt") devices answered"
	fi
else
	kldstat -q -n ng_ubt.ko && check bt-ng-ubt FAIL "ng_ubt loaded but no ubt0 node" ||
	    check bt-ng-ubt SKIP "no ubt0 (adapter absent or ng_ubt not loaded)"
fi

# --- dock Ethernet ----------------------------------------------------------------
if ifconfig ure0 > "$O/ure0.txt" 2>&1; then
	grep -q 'status: active' "$O/ure0.txt" &&
	    check ure0-link PASS "$(grep media: "$O/ure0.txt" | tr -s ' \t' ' ')" ||
	    check ure0-link FAIL "ure0 present, no carrier (cable/dock?)"
else
	check ure0-link SKIP "no ure0 (dock not connected)"
fi

# --- OTel services with a file target ----------------------------------------------
D=$O/otel-services; mkdir -p "$D/out"; chmod 755 "$D"
printf 'export { target = "file"; directory = "%s"; }\n' "$D/out" > "$D/otel.conf"
otelconf -f "$D/otel.conf" check -eqt > "$D/otelconf-check.txt" 2>&1 &&
    check otelconf-file-target PASS "$(cat "$D/otelconf-check.txt")" ||
    check otelconf-file-target FAIL "$(cat "$D/otelconf-check.txt")"
svcs="otel_hwstat otelpfd otel_dtrace"
service auditd onestatus > /dev/null 2>&1 && svcs="$svcs otelauditd" ||
    check otelauditd SKIP "auditd not running (otelauditd needs the audit pipe)"
started=""
for s in $svcs; do
	if service "$s" onestatus > /dev/null 2>&1; then
		check "svc-$s" SKIP "already running from your configuration; left untouched"
		continue
	fi
	service -E "OTELCONF_FILE=$D/otel.conf" "$s" onestart > "$D/$s.start" 2>&1
	started="$started $s"
	at_cleanup "service $s onestop >/dev/null 2>&1"
done
# otel_dtrace exports one cumulative snapshot per otel_dtrace_window
# (default 60 s), so wait past one window; generate login-class audit
# records (su) so otelauditd has something to export.
wait=30
case " $started " in *" otel_dtrace "*)
	w=$(sysrc -n otel_dtrace_window 2>/dev/null || echo 60)
	[ "$w" -ge 15 ] 2>/dev/null || w=60
	wait=$((w + 15)) ;;
esac
log "services started:$started; collecting for $wait s"
case " $started " in *" otelauditd "*)
	sleep 3
	for i in 1 2 3; do su -m nobody -c /usr/bin/true > /dev/null 2>&1; done ;;
esac
sleep $wait
for s in $started; do
	case $s in otel_hwstat) f=hwstat ;; otel_dtrace) f=bsdinstruments ;; *) f=$s ;; esac
	service "$s" onestatus > "$D/$s.status" 2>&1 || log "$s not running: $(cat "$D/$s.start" | tail -2)"
	if [ -s "$D/out/$f.jsonl" ] && "$B/otlp_validate" "$D/out/$f.jsonl" > "$D/$f.validate" 2>&1; then
		check "svc-$s-file-export" PASS "$(cat "$D/$f.validate")"
	else
		check "svc-$s-file-export" FAIL "$(tail -1 "$D/$f.validate" 2>/dev/null; tail -1 "$D/$s.start")"
	fi
	service "$s" onestop > "$D/$s.stop" 2>&1
	sleep 1
	service "$s" onestatus > /dev/null 2>&1 && check "svc-$s-stopped" FAIL "still running" ||
	    check "svc-$s-stopped" PASS
done

# --- podman port publishing through OpenBSD PF --------------------------------------
if pkg info -e containernetworking-plugins 2>/dev/null; then
	repo=$(pkg query '%R' containernetworking-plugins)
	pm=/usr/local/libexec/cni/portmap
	if [ "$repo" != 5BSD-ports ] || ! strings "$pm" 2>/dev/null | grep -q 'rdr-to'; then
		check podman-pf-portmap SKIP "containernetworking-plugins is from repository '$repo' (FreeBSD build, emits 'rdr pass' for FreeBSD pf); install the 5BSD-ports build (/usr/obj/5BSD-ports net/containernetworking-plugins) to test publishing through OpenBSD PF"
	elif ! command -v podman > /dev/null; then
		check podman-pf-portmap SKIP "podman not installed"
	else
		img=${HT_PODMAN_IMAGE:-$(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | head -1)}
		if [ -z "$img" ]; then
			check podman-pf-portmap SKIP "no local container image (set HT_PODMAN_IMAGE; the kit does not pull)"
		else
			podman run -d --name ht-portmap -p 127.0.0.1:18080:8080 "$img" \
			    sh -c 'while :; do echo HOSTTEST-PODMAN | { nc -l 8080 2>/dev/null || nc -l -p 8080; }; done' > "$O/podman-run.txt" 2>&1
			at_cleanup "podman rm -f ht-portmap >/dev/null 2>&1"
			sleep 3
			pfctl -a 'cni-rdr/*' -s rules > "$O/pf-cni-rules.txt" 2>&1
			pfctl -a 'cni-rdr' -s Anchors >> "$O/pf-cni-rules.txt" 2>&1
			got=$(printf '' | nc -w 3 127.0.0.1 18080 2>&1)
			[ "$got" = HOSTTEST-PODMAN ] && check podman-pf-portmap PASS "published port answered; rules: $(grep -c rdr-to "$O/pf-cni-rules.txt") rdr-to" ||
			    check podman-pf-portmap FAIL "got '$got' (pf-cni-rules.txt)"
			podman rm -f ht-portmap > /dev/null 2>&1
		fi
	fi
else
	check podman-pf-portmap SKIP "containernetworking-plugins not installed"
fi

sha256 -q /etc/rc.conf /etc/otel.conf /etc/pf.conf 2>/dev/null > "$O/config-after.sha256"
cmp -s "$O/config-before.sha256" "$O/config-after.sha256" && check system-config-unchanged PASS ||
    check system-config-unchanged FAIL "rc.conf/otel.conf/pf.conf changed during the phase"
phase_end
