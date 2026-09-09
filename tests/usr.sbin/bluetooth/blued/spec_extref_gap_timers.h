/*
 * EXTERNAL REFERENCE ORACLE: GAP timers and constants (the TGAP table).
 *
 * Hand-transcribed from the specification text named below.  Every value is
 * traceable to that named external source; nothing here was derived from
 * blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * Almost every "our defaults are fine" argument in the advertising, scanning
 * and connection-parameter code appeals, implicitly, to one of these numbers.
 * Pinning the table means such an argument can be checked instead of
 * believed.  Note the Requirement column: the overwhelming majority of the
 * table is *Recommended*, and exactly one entry -- TGAP(lim_adv_timeout) --
 * is a *Required value*.  A review that treats a recommended value as
 * mandatory is as wrong as one that ignores the required one.
 *
 * SOURCE
 * ------
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   Vol 3, Part C, Appendix A "Timers and Constants", text lines 68250-68420.
 *   Column 3 of that table ("Requirement or Recommendation") is reproduced
 *   here as the _REQUIRED / _RECOMMENDED suffix on each macro group.
 *
 * UNITS
 * -----
 * Values are given in microseconds (US) or milliseconds (MS) as marked, not
 * in HCI 0.625 ms / 1.25 ms units, precisely so that a conversion bug in our
 * code cannot be laundered through this header.  Convert at the point of use.
 */

#ifndef SPEC_EXTREF_GAP_TIMERS_H
#define SPEC_EXTREF_GAP_TIMERS_H

/*
 * -------------------------------------------------------------------------
 * Advertising intervals.  All RECOMMENDED values.
 *
 * "fast" applies when the advertising was user initiated; "slow" applies to
 * background advertising in any discoverable or connectable mode.
 * -------------------------------------------------------------------------
 */

/*
 * TGAP(adv_fast_interval1): 30 ms to 60 ms on the LE 1M PHY, when user
 * initiated, in: Undirected Connectable Mode; Limited Discoverable Mode
 * sending connectable undirected advertising events; General Discoverable
 * Mode sending connectable undirected advertising events; Directed
 * Connectable Mode sending low duty cycle directed advertising events.
 */
#define SPEC_TGAP_ADV_FAST_INTERVAL1_MIN_MS_RECOMMENDED		30
#define SPEC_TGAP_ADV_FAST_INTERVAL1_MAX_MS_RECOMMENDED		60

/* TGAP(adv_fast_interval1_coded): 90 ms to 180 ms, same modes, LE Coded PHY. */
#define SPEC_TGAP_ADV_FAST_INTERVAL1_CODED_MIN_MS_RECOMMENDED	90
#define SPEC_TGAP_ADV_FAST_INTERVAL1_CODED_MAX_MS_RECOMMENDED	180

/*
 * TGAP(adv_fast_interval2): 100 ms to 150 ms on the LE 1M PHY, when user
 * initiated and sending NON-CONNECTABLE advertising events, in:
 * Non-Discoverable Mode; Non-Connectable Mode; Limited Discoverable Mode;
 * General Discoverable Mode.
 */
#define SPEC_TGAP_ADV_FAST_INTERVAL2_MIN_MS_RECOMMENDED		100
#define SPEC_TGAP_ADV_FAST_INTERVAL2_MAX_MS_RECOMMENDED		150

/* TGAP(adv_fast_interval2_coded): 300 ms to 450 ms, same modes, LE Coded PHY. */
#define SPEC_TGAP_ADV_FAST_INTERVAL2_CODED_MIN_MS_RECOMMENDED	300
#define SPEC_TGAP_ADV_FAST_INTERVAL2_CODED_MAX_MS_RECOMMENDED	450

/* TGAP(adv_fast_period): 30 s minimum time to advertise when user initiated. */
#define SPEC_TGAP_ADV_FAST_PERIOD_MS_RECOMMENDED		30000

/*
 * TGAP(adv_slow_interval): 1 s to 1.2 s on the LE 1M PHY, background
 * advertising in any discoverable or connectable mode.
 */
#define SPEC_TGAP_ADV_SLOW_INTERVAL_MIN_MS_RECOMMENDED		1000
#define SPEC_TGAP_ADV_SLOW_INTERVAL_MAX_MS_RECOMMENDED		1200

/* TGAP(adv_slow_interval_coded): 3 s to 3.6 s, LE Coded PHY. */
#define SPEC_TGAP_ADV_SLOW_INTERVAL_CODED_MIN_MS_RECOMMENDED	3000
#define SPEC_TGAP_ADV_SLOW_INTERVAL_CODED_MAX_MS_RECOMMENDED	3600

/*
 * -------------------------------------------------------------------------
 * The ONE required value in the whole table.
 *
 * TGAP(lim_adv_timeout) = 180 s, "Maximum time to remain advertising when in
 * the limited discoverable mode", marked "Required value".  Vol 3 Part C
 * Section 9.2.3.2 (text line 65007) states the same rule in prose: "Devices
 * shall remain in the limited discoverable mode no longer than
 * TGAP(lim_adv_timeout)."
 * -------------------------------------------------------------------------
 */
#define SPEC_TGAP_LIM_ADV_TIMEOUT_MS_REQUIRED			180000

/*
 * -------------------------------------------------------------------------
 * Scanning.  All RECOMMENDED values.
 *
 * The interval/window pairs below are the GAP-recommended scan
 * configurations.  scan_fast is ~50% duty cycle (30 ms window in a 30-60 ms
 * interval); scan_slow1 is ~0.88% (11.25 ms in 1.28 s); scan_slow2 is ~0.88%
 * (22.5 ms in 2.56 s).
 * -------------------------------------------------------------------------
 */
#define SPEC_TGAP_SCAN_FAST_INTERVAL_MIN_MS_RECOMMENDED		30
#define SPEC_TGAP_SCAN_FAST_INTERVAL_MAX_MS_RECOMMENDED		60
#define SPEC_TGAP_SCAN_FAST_WINDOW_MS_RECOMMENDED		30
#define SPEC_TGAP_SCAN_FAST_PERIOD_MS_RECOMMENDED		30720

#define SPEC_TGAP_SCAN_FAST_INTERVAL_CODED_MIN_MS_RECOMMENDED	90
#define SPEC_TGAP_SCAN_FAST_INTERVAL_CODED_MAX_MS_RECOMMENDED	180
#define SPEC_TGAP_SCAN_FAST_WINDOW_CODED_MS_RECOMMENDED		90

/* Background scanning, LE 1M PHY.  Times in tenths of a millisecond where the
 * spec value is not a whole number of milliseconds (11.25 ms, 22.5 ms). */
#define SPEC_TGAP_SCAN_SLOW_INTERVAL1_MS_RECOMMENDED		1280
#define SPEC_TGAP_SCAN_SLOW_WINDOW1_TENTHS_MS_RECOMMENDED	112	/* 11.25 ms */
#define SPEC_TGAP_SCAN_SLOW_INTERVAL2_MS_RECOMMENDED		2560
#define SPEC_TGAP_SCAN_SLOW_WINDOW2_TENTHS_MS_RECOMMENDED	225	/* 22.5 ms */

/* Background scanning, LE Coded PHY. */
#define SPEC_TGAP_SCAN_SLOW_INTERVAL1_CODED_MS_RECOMMENDED	3840
#define SPEC_TGAP_SCAN_SLOW_WINDOW1_CODED_TENTHS_MS_RECOMMENDED	337	/* 33.75 ms */
#define SPEC_TGAP_SCAN_SLOW_INTERVAL2_CODED_MS_RECOMMENDED	7680
#define SPEC_TGAP_SCAN_SLOW_WINDOW2_CODED_TENTHS_MS_RECOMMENDED	675	/* 67.5 ms */

/*
 * Discovery-procedure minimum scan durations.  Vol 3 Part C Sections 9.2.5.2
 * (limited discovery, text line 65156) and 9.2.6.2 (general discovery, text
 * line 65247) require the observer to scan for at least these.
 */
#define SPEC_TGAP_LIM_DISC_SCAN_MIN_MS_RECOMMENDED		10240
#define SPEC_TGAP_LIM_DISC_SCAN_MIN_CODED_MS_RECOMMENDED	30720
#define SPEC_TGAP_GEN_DISC_SCAN_MIN_MS_RECOMMENDED		10240
#define SPEC_TGAP_GEN_DISC_SCAN_MIN_CODED_MS_RECOMMENDED	30720

/* Scan interval used in the limited discovery procedure. */
#define SPEC_TGAP_LIM_DISC_SCAN_INT_TENTHS_MS_RECOMMENDED	112	/* 11.25 ms */
#define SPEC_TGAP_LIM_DISC_SCAN_INT_CODED_TENTHS_MS_RECOMMENDED	337	/* 33.75 ms */

/*
 * -------------------------------------------------------------------------
 * Connection establishment and parameter update.  All RECOMMENDED values.
 * -------------------------------------------------------------------------
 */

/*
 * TGAP(initial_conn_interval): 30 ms to 50 ms on the LE 1M PHY, "upon any
 * connection establishment".
 */
#define SPEC_TGAP_INITIAL_CONN_INTERVAL_MIN_MS_RECOMMENDED	30
#define SPEC_TGAP_INITIAL_CONN_INTERVAL_MAX_MS_RECOMMENDED	50
#define SPEC_TGAP_INITIAL_CONN_INTERVAL_CODED_MIN_MS_RECOMMENDED	90
#define SPEC_TGAP_INITIAL_CONN_INTERVAL_CODED_MAX_MS_RECOMMENDED	150

/*
 * TGAP(conn_pause_peripheral) = 5 s: "Minimum time upon connection
 * establishment before the Peripheral starts a connection update procedure".
 * Vol 3 Part C Section 9.3.12 (text line 65932) states the rule in prose.
 * This is the delay a Peripheral must observe before sending an L2CAP LE
 * Connection Parameter Update Request or an LL_CONNECTION_PARAM_REQ.
 */
#define SPEC_TGAP_CONN_PAUSE_PERIPHERAL_MS_RECOMMENDED		5000

/* TGAP(conn_pause_central) = 1 s: Central idle timer. */
#define SPEC_TGAP_CONN_PAUSE_CENTRAL_MS_RECOMMENDED		1000

/*
 * TGAP(conn_param_timeout) = 30 s: "Connection parameter update notification
 * timer when performing the connection parameter update procedure".  This is
 * the response timeout for the L2CAP LE Connection Parameter Update Request,
 * not a rate limit.
 */
#define SPEC_TGAP_CONN_PARAM_TIMEOUT_MS_RECOMMENDED		30000

/*
 * -------------------------------------------------------------------------
 * Privacy.
 * -------------------------------------------------------------------------
 */

/*
 * TGAP(private_addr_int) = 15 min, "Maximum time interval between private
 * address change", Recommended value.
 *
 * The hard bound is stated in prose rather than in the table.  Vol 3 Part C
 * Section 10.7 (text line 67197), verbatim:
 *   "The value of TGAP(private_addr_int) shall not be greater than 1 hour."
 *
 * So: 15 minutes is a recommendation; one hour is a shall.  Note also the
 * Notes at text lines 67120, 67160, 67176 and 67199 -- the timer "need not be
 * run" when the corresponding role is idle (a Peripheral not advertising, a
 * Central not scanning or initiating, a Broadcaster not advertising, an
 * Observer not scanning).  A host that rotates on a free-running wall clock
 * regardless of role activity is conformant but does more work than required.
 */
#define SPEC_TGAP_PRIVATE_ADDR_INT_SEC_RECOMMENDED		900	/* 15 min */
#define SPEC_TGAP_PRIVATE_ADDR_INT_SEC_MAX_SHALL		3600	/* 1 hour */

/*
 * The HCI range for LE Set RPA Timeout (Vol 4 Part E Section 7.8.45) is a
 * separate constraint from the GAP bound above; it is pinned in
 * spec_extref_gap_privacy.h.
 */

#endif /* SPEC_EXTREF_GAP_TIMERS_H */
