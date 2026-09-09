/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Device Certificate validation (MshPRT_v1.1.1 Section 5.5).
 *
 * Certificate-based provisioning delivers the Provisionee's OOB Public Key
 * inside an X.509 Device Certificate rather than out of band by hand.  The
 * certificate is retrieved as a provisioning record (mesh_prov_records.h) or
 * over the Internet (Section 5.6), and Section 5.5.1 is unambiguous about what
 * has to happen next:
 *
 *	"The Provisioner shall use the Certification Path Validation procedure
 *	 defined in IETF RFC 5280 [12] ... to validate the Device Certificate
 *	 before using the contained OOB Public Key in provisioning the device."
 *
 * So the public key in a certificate is worth exactly what the path validation
 * behind it is worth.  This module performs that validation with OpenSSL's
 * X509_verify_cert() -- the same libcrypto the provisioning ECDH already
 * depends on -- against a trust anchor the operator configures, and then
 * enforces the Device Certificate profile of Section 5.5.1.1 on top of it.
 * Nothing here returns a public key that has not been through both.
 *
 * The validation boundary, stated plainly:
 *
 *   IN	   RFC 5280 certification path validation to a configured trust anchor
 *	   (signatures, validity dates, name chaining, basic constraints and
 *	   the CA path length, key usage on the CA certificates), then the
 *	   Section 5.5.1.1 profile: v3, ecdsa-with-SHA256, keyAgreement as the
 *	   only key usage, cA FALSE with no pathLenConstraint, the extensions
 *	   Section 5.5.1.1.4 forbids, a subjectPublicKeyInfo that is an
 *	   id-ecPublicKey on secp256r1, and the Common Name binding of Section
 *	   5.5.1.1.4.6 -- the Device UUID must match the device being
 *	   provisioned, and a CID/PID, if present, must match composition data
 *	   and must be present as a pair.
 *
 *   OUT	Revocation.  Section 5.5.1 places certificate revocation
 *		("How Device Certificate revocations are processed") out of
 *		scope, and no CRL or OCSP fetch is attempted; a CRL
 *		distribution points or freshest CRL extension is accepted and
 *		ignored.  A Provisioner that needs revocation must supply a
 *		trust anchor store whose CRLs it manages itself.
 *
 *   OUT	Certificate policy processing.  The certificate policies
 *		extension is required to be marked critical when present
 *		(Section 5.5.1.1.4.13) and is verified to be present and
 *		critical when the caller asks for it, but the policy OIDs
 *		themselves are not interpreted against an initial policy set.
 *
 *   OUT	Section 5.6 retrieval over the Internet.  A certificate that
 *		arrives by that route is validated here identically; fetching
 *		it is not implemented.
 *
 * Fail-closed is the whole point: with no trust anchor configured the verdict
 * is MESH_PROV_CERT_NO_ANCHOR and no key is produced.  There is deliberately
 * no "parse the certificate and use its key without validating it" entry
 * point, because a security procedure that looks implemented and is not is
 * worse than one that is absent.
 */

#ifndef _MESH_PROV_CERT_H_
#define _MESH_PROV_CERT_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_provision.h"

/* Verdicts.  Anything other than MESH_PROV_CERT_OK yields no public key. */
enum mesh_prov_cert_verdict {
	MESH_PROV_CERT_OK = 0,
	MESH_PROV_CERT_NO_ANCHOR,	/* no trust anchor configured */
	MESH_PROV_CERT_ANCHOR_LOAD,	/* the configured anchors did not load */
	MESH_PROV_CERT_DECODE,		/* not a DER X.509 certificate */
	MESH_PROV_CERT_ROOT_IN_CHAIN,	/* Section 5.4.2.6.5: root on the device */
	MESH_PROV_CERT_PATH,		/* RFC 5280 path validation failed */
	MESH_PROV_CERT_PROFILE,		/* Section 5.5.1.1 constraint violated */
	MESH_PROV_CERT_UUID,		/* Common Name UUID is not this device */
	MESH_PROV_CERT_CID_PID,		/* Common Name CID/PID mismatch */
	MESH_PROV_CERT_KEY,		/* not an id-ecPublicKey on secp256r1 */
	MESH_PROV_CERT_INTERNAL,	/* out of memory / libcrypto failure */
	MESH_PROV_CERT_ABSENT,		/* the device stores no Device Certificate */
};

/* Longest Common Name rendered back to the operator. */
#define	MESH_PROV_CERT_CN_MAX		192
#define	MESH_PROV_CERT_DETAIL_MAX	160

/*
 * What the Provisioner requires of the certificate.  roots_file (a PEM bundle)
 * and roots_dir (an OpenSSL hashed directory) are the trust anchors; at least
 * one must be set or the verdict is MESH_PROV_CERT_NO_ANCHOR.  Both are
 * borrowed pointers: a caller that hands this policy to a provisioning session
 * must keep the strings alive for as long as that session runs.
 *
 * uuid is the Device UUID of the device being provisioned, which Section
 * 5.5.1.1.4.6 requires the Provisioner to check against the Common Name
 * "before using the OOB Public Key in the certificate".  cid / pid, when the
 * caller has them from composition data, are checked against the BCID: / BPID:
 * fields of the Common Name if those are present.
 *
 * require_policies rejects a certificate with no certificate policies
 * extension, which Section 5.5.1.1.4.13 explicitly permits a Provisioner to
 * do ("A Provisioner may reject a Device Certificate that does not contain the
 * certificate policies extension").  require_cid_pid likewise rejects one
 * whose Common Name carries neither ("A Provisioner may reject a certificate
 * that does not contain the CID value and the PID value").
 *
 * verify_time, when non-zero, is the UNIX time at which the certificate
 * validity periods are judged, in place of the current time.
 */
struct mesh_prov_cert_policy {
	const char	*roots_file;
	const char	*roots_dir;
	uint8_t		uuid[16];
	int		have_uuid;
	uint16_t	cid;
	uint16_t	pid;
	int		have_cid_pid;
	int		require_policies;
	int		require_cid_pid;
	int64_t		verify_time;
};

/* The verdict and everything read out of an accepted certificate. */
struct mesh_prov_cert_result {
	int		verdict;		/* enum mesh_prov_cert_verdict */
	int		x509_error;		/* X509_V_ERR_* on _PATH */
	int		depth;			/* path depth of x509_error */
	char		detail[MESH_PROV_CERT_DETAIL_MAX];
	char		subject_cn[MESH_PROV_CERT_CN_MAX];
	uint8_t		pubkey[MESH_PROV_PUBKEY_LEN];	/* X || Y, big-endian */
	int		have_pubkey;
	uint8_t		uuid[16];		/* Device UUID from the CN */
	int		have_uuid;
	uint16_t	cid;
	uint16_t	pid;
	int		have_cid_pid;
};

/*
 * Validate a Device Certificate and, only on success, hand back its OOB Public
 * Key.  leaf is the DER Device Certificate; inter[0..ninter-1] are the DER
 * intermediate certificates in the order Section 5.4.2.6.5 defines them
 * (Intermediate Certificate 1 validates the Device Certificate, Intermediate
 * Certificate M validates M-1).  Returns 0 when res->verdict is
 * MESH_PROV_CERT_OK and -1 otherwise; res always carries the verdict.
 */
int	mesh_prov_cert_verify(const uint8_t *leaf, size_t leaf_len,
	    const uint8_t *const *inter, const size_t *inter_len, size_t ninter,
	    const struct mesh_prov_cert_policy *pol,
	    struct mesh_prov_cert_result *res);

/* One-word rendering of a verdict, for control-plane replies and logs. */
const char *mesh_prov_cert_verdict_str(int verdict);

#endif /* _MESH_PROV_CERT_H_ */
