/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Alex Teaca <iateaca@FreeBSD.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
 *
 */

#include <sys/cdefs.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#include <pthread_np.h>
#include <unistd.h>
#ifdef BHYVE_SNAPSHOT
#include <machine/vmm_snapshot.h>
#endif

#include "pci_hda.h"
#include "pci_hda_model.h"
#include "audio.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

/*
 * HDA Codec defines
 */
#define INTEL_VENDORID				0x8086

#define HDA_CODEC_SUBSYSTEM_ID			((INTEL_VENDORID << 16) | 0x01)
#define HDA_CODEC_ROOT_NID			0x00
#define HDA_CODEC_FG_NID			0x01
#define HDA_CODEC_AUDIO_OUTPUT_NID		0x02
#define HDA_CODEC_PIN_OUTPUT_NID		0x03
#define HDA_CODEC_AUDIO_INPUT_NID		0x04
#define HDA_CODEC_PIN_INPUT_NID			0x05

#define HDA_CODEC_NODES_COUNT			(HDA_CODEC_PIN_INPUT_NID + 1)

#define HDA_CODEC_STREAMS_COUNT			0x02
#define HDA_CODEC_STREAM_OUTPUT			0x00
#define HDA_CODEC_STREAM_INPUT			0x01

#define HDA_CODEC_PARAMS_COUNT			0x14
_Static_assert(HDA_CODEC_PARAMS_COUNT == HDA_CODEC_MODEL_PARAMS_COUNT,
    "codec parameter table width must match the model bound");
#define HDA_CODEC_CONN_LIST_COUNT		0x01
#define HDA_CODEC_RESPONSE_EX_UNSOL		0x10
#define HDA_CODEC_RESPONSE_EX_SOL		0x00
#define HDA_CODEC_AMP_NUMSTEPS			0x4a

#define HDA_CODEC_SUPP_STREAM_FORMATS_PCM				\
	(1 << HDA_PARAM_SUPP_STREAM_FORMATS_PCM_SHIFT)

#define HDA_CODEC_FMT_BASE_MASK			(0x01 << 14)

#define HDA_CODEC_FMT_MULT_MASK			(0x07 << 11)
#define HDA_CODEC_FMT_MULT_2			(0x01 << 11)
#define HDA_CODEC_FMT_MULT_3			(0x02 << 11)
#define HDA_CODEC_FMT_MULT_4			(0x03 << 11)

#define HDA_CODEC_FMT_DIV_MASK			0x07
#define HDA_CODEC_FMT_DIV_SHIFT			8

#define HDA_CODEC_FMT_BITS_MASK			(0x07 << 4)
#define HDA_CODEC_FMT_BITS_8			(0x00 << 4)
#define HDA_CODEC_FMT_BITS_16			(0x01 << 4)
#define HDA_CODEC_FMT_BITS_24			(0x03 << 4)
#define HDA_CODEC_FMT_BITS_32			(0x04 << 4)

#define HDA_CODEC_FMT_CHAN_MASK			(0x0f << 0)

#define HDA_CODEC_AUDIO_WCAP_OUTPUT					\
	(0x00 << HDA_PARAM_AUDIO_WIDGET_CAP_TYPE_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_INPUT					\
	(0x01 << HDA_PARAM_AUDIO_WIDGET_CAP_TYPE_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_PIN					\
	(0x04 << HDA_PARAM_AUDIO_WIDGET_CAP_TYPE_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_CONN_LIST					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_CONN_LIST_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_FORMAT_OVR					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_FORMAT_OVR_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_AMP_OVR					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_AMP_OVR_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_OUT_AMP					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_OUT_AMP_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_IN_AMP					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_IN_AMP_SHIFT)
#define HDA_CODEC_AUDIO_WCAP_STEREO					\
	(1 << HDA_PARAM_AUDIO_WIDGET_CAP_STEREO_SHIFT)

#define HDA_CODEC_PIN_CAP_OUTPUT					\
	(1 << HDA_PARAM_PIN_CAP_OUTPUT_CAP_SHIFT)
#define HDA_CODEC_PIN_CAP_INPUT						\
	(1 << HDA_PARAM_PIN_CAP_INPUT_CAP_SHIFT)
#define HDA_CODEC_PIN_CAP_PRESENCE_DETECT				\
	(1 << HDA_PARAM_PIN_CAP_PRESENCE_DETECT_CAP_SHIFT)

#define HDA_CODEC_OUTPUT_AMP_CAP_MUTE_CAP				\
	(1 << HDA_PARAM_OUTPUT_AMP_CAP_MUTE_CAP_SHIFT)
#define HDA_CODEC_OUTPUT_AMP_CAP_STEPSIZE				\
	(0x03 << HDA_PARAM_OUTPUT_AMP_CAP_STEPSIZE_SHIFT)
#define HDA_CODEC_OUTPUT_AMP_CAP_NUMSTEPS				\
	(HDA_CODEC_AMP_NUMSTEPS << HDA_PARAM_OUTPUT_AMP_CAP_NUMSTEPS_SHIFT)
#define HDA_CODEC_OUTPUT_AMP_CAP_OFFSET					\
	(HDA_CODEC_AMP_NUMSTEPS << HDA_PARAM_OUTPUT_AMP_CAP_OFFSET_SHIFT)

#define HDA_CODEC_SET_AMP_GAIN_MUTE_MUTE	0x80
#define HDA_CODEC_SET_AMP_GAIN_MUTE_GAIN_MASK	0x7f

#define HDA_CODEC_PIN_SENSE_PRESENCE_PLUGGED	(1U << 31)
#define HDA_CODEC_PIN_WIDGET_CTRL_OUT_ENABLE				\
	(1 << HDA_CMD_GET_PIN_WIDGET_CTRL_OUT_ENABLE_SHIFT)
#define HDA_CODEC_PIN_WIDGET_CTRL_IN_ENABLE				\
	(1 << HDA_CMD_GET_PIN_WIDGET_CTRL_IN_ENABLE_SHIFT)

#define HDA_CONFIG_DEFAULTCONF_COLOR_BLACK				\
	(0x01 << HDA_CONFIG_DEFAULTCONF_COLOR_SHIFT)
#define HDA_CONFIG_DEFAULTCONF_COLOR_RED				\
	(0x05 << HDA_CONFIG_DEFAULTCONF_COLOR_SHIFT)

#define HDA_CODEC_BUF_SIZE			HDA_FIFO_SIZE

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


/*
 * HDA Audio Context data structures
 */

typedef void (*transfer_func_t)(void *arg);
typedef int (*setup_func_t)(void *arg);

struct hda_audio_ctxt {
	char name[64];
	uint8_t run;
	uint8_t started;
	uint8_t shutdown;
	void *priv;
	pthread_t tid;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	setup_func_t do_setup;
	transfer_func_t do_transfer;
};

/*
 * HDA Audio Context module function declarations
 */

static void *hda_audio_ctxt_thr(void *arg);
static int hda_audio_ctxt_init(struct hda_audio_ctxt *actx, const char *tname,
    transfer_func_t do_transfer, setup_func_t do_setup, void *priv);
static int hda_audio_ctxt_start(struct hda_audio_ctxt *actx);
static int hda_audio_ctxt_stop(struct hda_audio_ctxt *actx);
static void hda_audio_ctxt_fini(struct hda_audio_ctxt *actx);

/*
 * HDA Codec data structures
 */

struct hda_codec_softc;

typedef uint32_t (*verb_func_t)(struct hda_codec_softc *sc, uint16_t verb,
				    uint16_t payload);

struct hda_codec_stream {
	uint8_t buf[HDA_CODEC_BUF_SIZE];
	uint8_t channel;
	_Atomic(uint16_t) fmt;
	_Atomic(uint8_t) stream;

	uint8_t left_gain;
	uint8_t right_gain;
	uint8_t left_mute;
	uint8_t right_mute;

	struct audio *aud;
	struct hda_audio_ctxt actx;
};

struct hda_codec_softc {
	uint32_t no_nodes;
	uint32_t subsystem_id;
	const uint32_t (*get_parameters)[HDA_CODEC_PARAMS_COUNT];
	const uint8_t (*conn_list)[HDA_CODEC_CONN_LIST_COUNT];
	const uint32_t *conf_default;
	const uint8_t *pin_ctrl_default;
	const verb_func_t *verb_handlers;

	struct hda_codec_inst *hci;
	struct hda_codec_stream streams[HDA_CODEC_STREAMS_COUNT];
};

/*
 * HDA Codec module function declarations
 */
static int hda_codec_init(struct hda_codec_inst *hci, const char *play,
    const char *rec);
static int hda_codec_reset(struct hda_codec_inst *hci);
static int hda_codec_command(struct hda_codec_inst *hci, uint32_t cmd_data);
static int hda_codec_notify(struct hda_codec_inst *hci, uint8_t run,
    uint8_t stream, uint8_t dir);

static int hda_codec_parse_format(uint16_t fmt, struct audio_params *params);

static uint32_t hda_codec_audio_output_nid(struct hda_codec_softc *sc,
    uint16_t verb, uint16_t payload);
static void hda_codec_audio_output_do_transfer(void *arg);
static int hda_codec_audio_output_do_setup(void *arg);
static uint32_t hda_codec_audio_input_nid(struct hda_codec_softc *sc,
    uint16_t verb, uint16_t payload);
static void hda_codec_audio_input_do_transfer(void *arg);
static int hda_codec_audio_input_do_setup(void *arg);

static uint32_t hda_codec_audio_inout_nid(struct hda_codec_stream *st,
    uint16_t verb, uint16_t payload);

/*
 * HDA Codec global data
 */

#define HDA_CODEC_ROOT_DESC						\
	[HDA_CODEC_ROOT_NID] = {					\
		[HDA_PARAM_VENDOR_ID] = INTEL_VENDORID,			\
		[HDA_PARAM_REVISION_ID] = 0xffff,			\
		/* 1 Subnode, StartNid = 1 */				\
		[HDA_PARAM_SUB_NODE_COUNT] = 0x00010001,		\
	},								\

#define HDA_CODEC_FG_COMMON_DESC					\
	[HDA_PARAM_FCT_GRP_TYPE] = HDA_PARAM_FCT_GRP_TYPE_NODE_TYPE_AUDIO,\
	/* B8 - B32, 8.0 - 192.0kHz */					\
	[HDA_PARAM_SUPP_PCM_SIZE_RATE] = (0x1f << 16) | 0x7ff,		\
	[HDA_PARAM_SUPP_STREAM_FORMATS] = HDA_CODEC_SUPP_STREAM_FORMATS_PCM,\
	[HDA_PARAM_INPUT_AMP_CAP] = 0x00,	/* None */		\
	[HDA_PARAM_OUTPUT_AMP_CAP] = 0x00,	/* None */		\
	[HDA_PARAM_GPIO_COUNT] = 0x00,					\

#define HDA_CODEC_FG_OUTPUT_DESC					\
	[HDA_CODEC_FG_NID] = {						\
		/* 2 Subnodes, StartNid = 2 */				\
		[HDA_PARAM_SUB_NODE_COUNT] = 0x00020002,		\
		HDA_CODEC_FG_COMMON_DESC				\
	},								\

#define HDA_CODEC_FG_INPUT_DESC						\
	[HDA_CODEC_FG_NID] = {						\
		/* 2 Subnodes, StartNid = 4 */				\
		[HDA_PARAM_SUB_NODE_COUNT] = 0x00040002,		\
		HDA_CODEC_FG_COMMON_DESC				\
	},								\

#define HDA_CODEC_FG_DUPLEX_DESC					\
	[HDA_CODEC_FG_NID] = {						\
		/* 4 Subnodes, StartNid = 2 */				\
		[HDA_PARAM_SUB_NODE_COUNT] = 0x00020004,		\
		HDA_CODEC_FG_COMMON_DESC				\
	},								\

#define HDA_CODEC_OUTPUT_DESC						\
	[HDA_CODEC_AUDIO_OUTPUT_NID] = {				\
		[HDA_PARAM_AUDIO_WIDGET_CAP] = 				\
				HDA_CODEC_AUDIO_WCAP_OUTPUT |		\
				HDA_CODEC_AUDIO_WCAP_FORMAT_OVR |	\
				HDA_CODEC_AUDIO_WCAP_AMP_OVR |		\
				HDA_CODEC_AUDIO_WCAP_OUT_AMP |		\
				HDA_CODEC_AUDIO_WCAP_STEREO,		\
		/* B16, 16.0 - 192.0kHz */				\
		[HDA_PARAM_SUPP_PCM_SIZE_RATE] = (0x02 << 16) | 0x7fc,	\
		[HDA_PARAM_SUPP_STREAM_FORMATS] =			\
				HDA_CODEC_SUPP_STREAM_FORMATS_PCM,	\
		[HDA_PARAM_INPUT_AMP_CAP] = 0x00,	/* None */	\
		[HDA_PARAM_CONN_LIST_LENGTH] = 0x00,			\
		[HDA_PARAM_OUTPUT_AMP_CAP] =				\
				HDA_CODEC_OUTPUT_AMP_CAP_MUTE_CAP |	\
				HDA_CODEC_OUTPUT_AMP_CAP_STEPSIZE |	\
				HDA_CODEC_OUTPUT_AMP_CAP_NUMSTEPS |	\
				HDA_CODEC_OUTPUT_AMP_CAP_OFFSET,	\
	},								\
	[HDA_CODEC_PIN_OUTPUT_NID] = {					\
		[HDA_PARAM_AUDIO_WIDGET_CAP] =				\
				HDA_CODEC_AUDIO_WCAP_PIN |		\
				HDA_CODEC_AUDIO_WCAP_CONN_LIST |	\
				HDA_CODEC_AUDIO_WCAP_STEREO,		\
		[HDA_PARAM_PIN_CAP] = HDA_CODEC_PIN_CAP_OUTPUT |	\
				      HDA_CODEC_PIN_CAP_PRESENCE_DETECT,\
		[HDA_PARAM_INPUT_AMP_CAP] = 0x00,	/* None */	\
		[HDA_PARAM_CONN_LIST_LENGTH] = 0x01,			\
		[HDA_PARAM_OUTPUT_AMP_CAP] = 0x00,	/* None */	\
	},								\

#define HDA_CODEC_INPUT_DESC						\
	[HDA_CODEC_AUDIO_INPUT_NID] = {					\
		[HDA_PARAM_AUDIO_WIDGET_CAP] =				\
				HDA_CODEC_AUDIO_WCAP_INPUT |		\
				HDA_CODEC_AUDIO_WCAP_CONN_LIST |	\
				HDA_CODEC_AUDIO_WCAP_FORMAT_OVR |	\
				HDA_CODEC_AUDIO_WCAP_AMP_OVR |		\
				HDA_CODEC_AUDIO_WCAP_IN_AMP |		\
				HDA_CODEC_AUDIO_WCAP_STEREO,		\
		/* B16, 16.0 - 192.0kHz */				\
		[HDA_PARAM_SUPP_PCM_SIZE_RATE] = (0x02 << 16) | 0x7fc,	\
		[HDA_PARAM_SUPP_STREAM_FORMATS] =			\
				HDA_CODEC_SUPP_STREAM_FORMATS_PCM,	\
		[HDA_PARAM_OUTPUT_AMP_CAP] = 0x00,	/* None */	\
		[HDA_PARAM_CONN_LIST_LENGTH] = 0x01,			\
		[HDA_PARAM_INPUT_AMP_CAP] =				\
				HDA_CODEC_OUTPUT_AMP_CAP_MUTE_CAP |	\
				HDA_CODEC_OUTPUT_AMP_CAP_STEPSIZE |	\
				HDA_CODEC_OUTPUT_AMP_CAP_NUMSTEPS |	\
				HDA_CODEC_OUTPUT_AMP_CAP_OFFSET,	\
	},								\
	[HDA_CODEC_PIN_INPUT_NID] = {					\
		[HDA_PARAM_AUDIO_WIDGET_CAP] =				\
				HDA_CODEC_AUDIO_WCAP_PIN |		\
				HDA_CODEC_AUDIO_WCAP_STEREO,		\
		[HDA_PARAM_PIN_CAP] = HDA_CODEC_PIN_CAP_INPUT |		\
				HDA_CODEC_PIN_CAP_PRESENCE_DETECT,	\
		[HDA_PARAM_INPUT_AMP_CAP] = 0x00,	/* None */	\
		[HDA_PARAM_OUTPUT_AMP_CAP] = 0x00,	/* None */	\
	},								\

static const uint32_t
hda_codec_output_parameters[HDA_CODEC_NODES_COUNT][HDA_CODEC_PARAMS_COUNT] = {
	HDA_CODEC_ROOT_DESC
	HDA_CODEC_FG_OUTPUT_DESC
	HDA_CODEC_OUTPUT_DESC
};

static const uint32_t
hda_codec_input_parameters[HDA_CODEC_NODES_COUNT][HDA_CODEC_PARAMS_COUNT] = {
	HDA_CODEC_ROOT_DESC
	HDA_CODEC_FG_INPUT_DESC
	HDA_CODEC_INPUT_DESC
};

static const uint32_t
hda_codec_duplex_parameters[HDA_CODEC_NODES_COUNT][HDA_CODEC_PARAMS_COUNT] = {
	HDA_CODEC_ROOT_DESC
	HDA_CODEC_FG_DUPLEX_DESC
	HDA_CODEC_OUTPUT_DESC
	HDA_CODEC_INPUT_DESC
};

static const uint8_t
hda_codec_conn_list[HDA_CODEC_NODES_COUNT][HDA_CODEC_CONN_LIST_COUNT] = {
	[HDA_CODEC_PIN_OUTPUT_NID] = {HDA_CODEC_AUDIO_OUTPUT_NID},
	[HDA_CODEC_AUDIO_INPUT_NID] = {HDA_CODEC_PIN_INPUT_NID},
};

static const uint32_t
hda_codec_conf_default[HDA_CODEC_NODES_COUNT] = {
	[HDA_CODEC_PIN_OUTPUT_NID] =					\
		HDA_CONFIG_DEFAULTCONF_CONNECTIVITY_JACK |
		HDA_CONFIG_DEFAULTCONF_DEVICE_LINE_OUT |
		HDA_CONFIG_DEFAULTCONF_COLOR_BLACK |
		(0x01 << HDA_CONFIG_DEFAULTCONF_ASSOCIATION_SHIFT),
	[HDA_CODEC_PIN_INPUT_NID] = HDA_CONFIG_DEFAULTCONF_CONNECTIVITY_JACK |
				    HDA_CONFIG_DEFAULTCONF_DEVICE_LINE_IN |
				    HDA_CONFIG_DEFAULTCONF_COLOR_RED |
			(0x02 << HDA_CONFIG_DEFAULTCONF_ASSOCIATION_SHIFT),
};

static const uint8_t
hda_codec_pin_ctrl_default[HDA_CODEC_NODES_COUNT] = {
	[HDA_CODEC_PIN_OUTPUT_NID] = HDA_CODEC_PIN_WIDGET_CTRL_OUT_ENABLE,
	[HDA_CODEC_PIN_INPUT_NID] = HDA_CODEC_PIN_WIDGET_CTRL_IN_ENABLE,
};

static const
verb_func_t hda_codec_verb_handlers[HDA_CODEC_NODES_COUNT] = {
	[HDA_CODEC_AUDIO_OUTPUT_NID] = hda_codec_audio_output_nid,
	[HDA_CODEC_AUDIO_INPUT_NID] = hda_codec_audio_input_nid,
};

/*
 * HDA Codec module function definitions
 */

static int
hda_codec_init(struct hda_codec_inst *hci, const char *play,
    const char *rec)
{
	struct hda_codec_softc *sc = NULL;
	struct hda_codec_stream *st = NULL;
	int err;

	if (hci == NULL || (play == NULL && rec == NULL))
		return (-1);

	sc = calloc(1, sizeof(*sc));
	if (!sc)
		return (-1);

	if (play && rec)
		sc->get_parameters = hda_codec_duplex_parameters;
	else {
		if (play)
			sc->get_parameters = hda_codec_output_parameters;
		else
			sc->get_parameters = hda_codec_input_parameters;
	}
	sc->subsystem_id = HDA_CODEC_SUBSYSTEM_ID;
	sc->no_nodes = HDA_CODEC_NODES_COUNT;
	sc->conn_list = hda_codec_conn_list;
	sc->conf_default = hda_codec_conf_default;
	sc->pin_ctrl_default = hda_codec_pin_ctrl_default;
	sc->verb_handlers = hda_codec_verb_handlers;
	sc->hci = hci;
	DPRINTF("HDA Codec nodes: %d", sc->no_nodes);

	/*
	 * Initialize the Audio Output stream
	 */
	if (play) {
		st = &sc->streams[HDA_CODEC_STREAM_OUTPUT];
		st->aud = audio_init(play, 1);
		if (!st->aud) {
			DPRINTF("Fail to init the output audio player");
			goto fail;
		}
		err = hda_audio_ctxt_init(&st->actx, "hda-audio-output",
		    hda_codec_audio_output_do_transfer,
		    hda_codec_audio_output_do_setup, sc);
		if (err != 0)
			goto fail;
	}

	/*
	 * Initialize the Audio Input stream
	 */
	if (rec) {
		st = &sc->streams[HDA_CODEC_STREAM_INPUT];
		st->aud = audio_init(rec, 0);
		if (!st->aud) {
			DPRINTF("Fail to init the input audio player");
			goto fail;
		}
		err = hda_audio_ctxt_init(&st->actx, "hda-audio-input",
		    hda_codec_audio_input_do_transfer,
		    hda_codec_audio_input_do_setup, sc);
		if (err != 0)
			goto fail;
	}

	hci->priv = sc;

	return (0);

fail:
	for (size_t i = 0; i < HDA_CODEC_STREAMS_COUNT; i++) {
		st = &sc->streams[i];
		hda_audio_ctxt_fini(&st->actx);
		audio_destroy(st->aud);
		st->aud = NULL;
	}
	free(sc);
	return (-1);
}

static int
hda_codec_reset(struct hda_codec_inst *hci)
{
	const struct hda_ops *hops = NULL;
	struct hda_codec_softc *sc = NULL;
	struct hda_codec_stream *st = NULL;
	int i;

	assert(hci);

	hops = hci->hops;
	assert(hops);

	sc = (struct hda_codec_softc *)hci->priv;
	assert(sc);

	for (i = 0; i < HDA_CODEC_STREAMS_COUNT; i++) {
		st = &sc->streams[i];
		(void)hda_audio_ctxt_stop(&st->actx);
		atomic_store_explicit(&st->stream, 0, memory_order_relaxed);
		atomic_store_explicit(&st->fmt, 0, memory_order_relaxed);
		st->channel = 0;
		st->left_gain = HDA_CODEC_AMP_NUMSTEPS;
		st->right_gain = HDA_CODEC_AMP_NUMSTEPS;
		st->left_mute = HDA_CODEC_SET_AMP_GAIN_MUTE_MUTE;
		st->right_mute = HDA_CODEC_SET_AMP_GAIN_MUTE_MUTE;
	}

	DPRINTF("cad: 0x%x", hci->cad);

	if (!hops->signal) {
		DPRINTF("The controller ops does not implement \
			 the signal function");
		return (-1);
	}

	return (hops->signal(hci));
}

static int
hda_codec_command(struct hda_codec_inst *hci, uint32_t cmd_data)
{
	const struct hda_ops *hops = NULL;
	struct hda_codec_softc *sc = NULL;
	uint8_t cad = 0, nid = 0;
	uint16_t verb = 0, payload = 0;
	uint32_t res = 0;

	/* 4 bits */
	cad = (cmd_data >> HDA_CMD_CAD_SHIFT) & 0x0f;
	/* 8 bits */
	nid = (cmd_data >> HDA_CMD_NID_SHIFT) & 0xff;

	if ((cmd_data & 0x70000) == 0x70000) {
		/* 12 bits */
		verb = (cmd_data >> HDA_CMD_VERB_12BIT_SHIFT) & 0x0fff;
		/* 8 bits */
		payload = cmd_data & 0xff;
	} else {
		/* 4 bits */
		verb = (cmd_data >> HDA_CMD_VERB_4BIT_SHIFT) & 0x0f;
		/* 16 bits */
		payload = cmd_data & 0xffff;
	}

	assert(hci);

	hops = hci->hops;
	assert(hops);

	sc = (struct hda_codec_softc *)hci->priv;
	assert(sc);

	if (cad != hci->cad || nid >= sc->no_nodes) {
		DPRINTF("Invalid command data");
		return (-1);
	}

	if (!hops->response) {
		DPRINTF("The controller ops does not implement \
			 the response function");
		return (-1);
	}

	switch (verb) {
	case HDA_CMD_VERB_GET_PARAMETER:
		if (hda_codec_get_parameter_valid(nid, sc->no_nodes, payload))
			res = sc->get_parameters[nid][payload];
		break;
	case HDA_CMD_VERB_GET_CONN_LIST_ENTRY:
		res = sc->conn_list[nid][0];
		break;
	case HDA_CMD_VERB_GET_PIN_WIDGET_CTRL:
		res = sc->pin_ctrl_default[nid];
		break;
	case HDA_CMD_VERB_GET_PIN_SENSE:
		res = HDA_CODEC_PIN_SENSE_PRESENCE_PLUGGED;
		break;
	case HDA_CMD_VERB_GET_CONFIGURATION_DEFAULT:
		res = sc->conf_default[nid];
		break;
	case HDA_CMD_VERB_GET_SUBSYSTEM_ID:
		res = sc->subsystem_id;
		break;
	default:
		assert(sc->verb_handlers);
		if (sc->verb_handlers[nid])
			res = sc->verb_handlers[nid](sc, verb, payload);
		else
			DPRINTF("Unknown VERB: 0x%x", verb);
		break;
	}

	DPRINTF("cad: 0x%x nid: 0x%x verb: 0x%x payload: 0x%x response: 0x%x",
	    cad, nid, verb, payload, res);

	return (hops->response(hci, res, HDA_CODEC_RESPONSE_EX_SOL));
}

static int
hda_codec_notify(struct hda_codec_inst *hci, uint8_t run,
    uint8_t stream, uint8_t dir)
{
	struct hda_codec_softc *sc = NULL;
	struct hda_codec_stream *st = NULL;
	struct hda_audio_ctxt *actx = NULL;
	int i;
	int err;

	assert(hci);
	assert(stream);

	sc = (struct hda_codec_softc *)hci->priv;
	assert(sc);

	i = dir ? HDA_CODEC_STREAM_OUTPUT : HDA_CODEC_STREAM_INPUT;
	st = &sc->streams[i];

	DPRINTF("run: %d, stream: 0x%x, st->stream: 0x%x dir: %d",
	    run, stream,
	    atomic_load_explicit(&st->stream, memory_order_relaxed), dir);

	if (stream != atomic_load_explicit(&st->stream,
	    memory_order_relaxed)) {
		DPRINTF("Stream not found");
		return (0);
	}

	actx = &st->actx;
	if (!actx->started)
		return (-1);

	if (run)
		err = hda_audio_ctxt_start(actx);
	else
		err = hda_audio_ctxt_stop(actx);

	return (err);
}

static int
hda_codec_parse_format(uint16_t fmt, struct audio_params *params)
{
	uint8_t div = 0;

	assert(params);

	/* Compute the Sample Rate */
	params->rate = (fmt & HDA_CODEC_FMT_BASE_MASK) ? 44100 : 48000;

	switch (fmt & HDA_CODEC_FMT_MULT_MASK) {
	case HDA_CODEC_FMT_MULT_2:
		params->rate *= 2;
		break;
	case HDA_CODEC_FMT_MULT_3:
		params->rate *= 3;
		break;
	case HDA_CODEC_FMT_MULT_4:
		params->rate *= 4;
		break;
	}

	div = (fmt >> HDA_CODEC_FMT_DIV_SHIFT) & HDA_CODEC_FMT_DIV_MASK;
	params->rate /= (div + 1);

	/* Compute the Bits per Sample */
	switch (fmt & HDA_CODEC_FMT_BITS_MASK) {
	case HDA_CODEC_FMT_BITS_8:
		params->format = AFMT_U8;
		break;
	case HDA_CODEC_FMT_BITS_16:
		params->format = AFMT_S16_LE;
		break;
	case HDA_CODEC_FMT_BITS_24:
		params->format = AFMT_S24_LE;
		break;
	case HDA_CODEC_FMT_BITS_32:
		params->format = AFMT_S32_LE;
		break;
	default:
		DPRINTF("Unknown format bits: 0x%x",
		    fmt & HDA_CODEC_FMT_BITS_MASK);
		return (-1);
	}

	/* Compute the Number of Channels */
	params->channels = (fmt & HDA_CODEC_FMT_CHAN_MASK) + 1;

	return (0);
}

static uint32_t
hda_codec_audio_output_nid(struct hda_codec_softc *sc, uint16_t verb,
    uint16_t payload)
{
	struct hda_codec_stream *st = &sc->streams[HDA_CODEC_STREAM_OUTPUT];
	int res;

	res = hda_codec_audio_inout_nid(st, verb, payload);

	return (res);
}

static void
hda_codec_audio_output_do_transfer(void *arg)
{
	const struct hda_ops *hops = NULL;
	struct hda_codec_softc *sc = (struct hda_codec_softc *)arg;
	struct hda_codec_inst *hci = NULL;
	struct hda_codec_stream *st = NULL;
	struct audio *aud = NULL;
	int err;

	hci = sc->hci;
	assert(hci);

	hops = hci->hops;
	assert(hops);

	st = &sc->streams[HDA_CODEC_STREAM_OUTPUT];
	aud = st->aud;

	err = hops->transfer(hci,
	    atomic_load_explicit(&st->stream, memory_order_relaxed), 1,
	    st->buf, sizeof(st->buf));
	if (err) {
		(void)hda_audio_ctxt_stop(&st->actx);
		return;
	}

	err = audio_playback(aud, st->buf, sizeof(st->buf));
	if (err != 0)
		(void)hda_audio_ctxt_stop(&st->actx);
}

static int
hda_codec_audio_output_do_setup(void *arg)
{
	struct hda_codec_softc *sc = (struct hda_codec_softc *)arg;
	struct hda_codec_stream *st = NULL;
	struct audio *aud = NULL;
	struct audio_params params;
	int err;

	st = &sc->streams[HDA_CODEC_STREAM_OUTPUT];
	aud = st->aud;

	err = hda_codec_parse_format(
	    atomic_load_explicit(&st->fmt, memory_order_relaxed), &params);
	if (err)
		return (-1);

	DPRINTF("rate: %d, channels: %d, format: 0x%x",
	    params.rate, params.channels, params.format);

	return (audio_set_params(aud, &params));
}

static uint32_t
hda_codec_audio_input_nid(struct hda_codec_softc *sc, uint16_t verb,
    uint16_t payload)
{
	struct hda_codec_stream *st = &sc->streams[HDA_CODEC_STREAM_INPUT];
	int res;

	res = hda_codec_audio_inout_nid(st, verb, payload);

	return (res);
}

static void
hda_codec_audio_input_do_transfer(void *arg)
{
	const struct hda_ops *hops = NULL;
	struct hda_codec_softc *sc = (struct hda_codec_softc *)arg;
	struct hda_codec_inst *hci = NULL;
	struct hda_codec_stream *st = NULL;
	struct audio *aud = NULL;
	int err;

	hci = sc->hci;
	assert(hci);

	hops = hci->hops;
	assert(hops);

	st = &sc->streams[HDA_CODEC_STREAM_INPUT];
	aud = st->aud;

	err = audio_record(aud, st->buf, sizeof(st->buf));
	if (err != 0) {
		(void)hda_audio_ctxt_stop(&st->actx);
		return;
	}

	if (hops->transfer(hci,
	    atomic_load_explicit(&st->stream, memory_order_relaxed), 0, st->buf,
	    sizeof(st->buf)) != 0)
		(void)hda_audio_ctxt_stop(&st->actx);
}

static int
hda_codec_audio_input_do_setup(void *arg)
{
	struct hda_codec_softc *sc = (struct hda_codec_softc *)arg;
	struct hda_codec_stream *st = NULL;
	struct audio *aud = NULL;
	struct audio_params params;
	int err;

	st = &sc->streams[HDA_CODEC_STREAM_INPUT];
	aud = st->aud;

	err = hda_codec_parse_format(
	    atomic_load_explicit(&st->fmt, memory_order_relaxed), &params);
	if (err)
		return (-1);

	DPRINTF("rate: %d, channels: %d, format: 0x%x",
	    params.rate, params.channels, params.format);

	return (audio_set_params(aud, &params));
}

static uint32_t
hda_codec_audio_inout_nid(struct hda_codec_stream *st, uint16_t verb,
    uint16_t payload)
{
	uint32_t res = 0;
	uint8_t mute = 0;
	uint8_t gain = 0;

	DPRINTF("%s verb: 0x%x, payload, 0x%x", st->actx.name, verb, payload);

	switch (verb) {
	case HDA_CMD_VERB_GET_CONV_FMT:
		res = atomic_load_explicit(&st->fmt, memory_order_relaxed);
		break;
	case HDA_CMD_VERB_SET_CONV_FMT:
		atomic_store_explicit(&st->fmt, payload, memory_order_relaxed);
		break;
	case HDA_CMD_VERB_GET_AMP_GAIN_MUTE:
		if (payload & HDA_CMD_GET_AMP_GAIN_MUTE_LEFT) {
			res = st->left_gain | st->left_mute;
			DPRINTF("GET_AMP_GAIN_MUTE_LEFT: 0x%x", res);
		} else {
			res = st->right_gain | st->right_mute;
			DPRINTF("GET_AMP_GAIN_MUTE_RIGHT: 0x%x", res);
		}
		break;
	case HDA_CMD_VERB_SET_AMP_GAIN_MUTE:
		mute = payload & HDA_CODEC_SET_AMP_GAIN_MUTE_MUTE;
		gain = payload & HDA_CODEC_SET_AMP_GAIN_MUTE_GAIN_MASK;

		if (payload & HDA_CMD_SET_AMP_GAIN_MUTE_LEFT) {
			st->left_mute = mute;
			st->left_gain = gain;
			DPRINTF("SET_AMP_GAIN_MUTE_LEFT: \
			    mute: 0x%x gain: 0x%x", mute, gain);
		}

		if (payload & HDA_CMD_SET_AMP_GAIN_MUTE_RIGHT) {
			st->right_mute = mute;
			st->right_gain = gain;
			DPRINTF("SET_AMP_GAIN_MUTE_RIGHT: \
			    mute: 0x%x gain: 0x%x", mute, gain);
		}
		break;
	case HDA_CMD_VERB_GET_CONV_STREAM_CHAN:
		res = (atomic_load_explicit(&st->stream,
		    memory_order_relaxed) << 4) | st->channel;
		break;
	case HDA_CMD_VERB_SET_CONV_STREAM_CHAN:
		st->channel = payload & 0x0f;
		atomic_store_explicit(&st->stream, (payload >> 4) & 0x0f,
		    memory_order_relaxed);
		DPRINTF("st->channel: 0x%x st->stream: 0x%x",
		    st->channel, atomic_load_explicit(&st->stream,
		    memory_order_relaxed));
		if (atomic_load_explicit(&st->stream, memory_order_relaxed) == 0)
			hda_audio_ctxt_stop(&st->actx);
		break;
	default:
		DPRINTF("Unknown VERB: 0x%x", verb);
		break;
	}

	return (res);
}

#ifdef BHYVE_SNAPSHOT
#define	HDA_CODEC_SNAPSHOT_MAGIC	0x31434448U	/* "HDC1" on disk */
#define	HDA_CODEC_SNAPSHOT_VERSION	1U

#define	HDA_CODEC_SNAPSHOT_SHAPE_OUTPUT	0U
#define	HDA_CODEC_SNAPSHOT_SHAPE_INPUT	1U
#define	HDA_CODEC_SNAPSHOT_SHAPE_DUPLEX	2U

static uint8_t
hda_codec_snapshot_shape(const struct hda_codec_softc *sc)
{

	if (sc->get_parameters == hda_codec_duplex_parameters)
		return (HDA_CODEC_SNAPSHOT_SHAPE_DUPLEX);
	if (sc->get_parameters == hda_codec_input_parameters)
		return (HDA_CODEC_SNAPSHOT_SHAPE_INPUT);
	return (HDA_CODEC_SNAPSHOT_SHAPE_OUTPUT);
}

/*
 * The audio backend (an open OSS device) is live external state: neither its
 * in-kernel sample buffer nor its descriptor identity is serialized.  A
 * restore destination reconstructs the backend from its own play/rec
 * configuration, and the controller restart path replays the restored
 * converter format into the backend via the stream setup callback.  Only
 * guest-programmed converter state travels in the record; in-flight samples
 * are transient (bounded by one FIFO) and are dropped, exactly as a real
 * codec loses in-flight samples across a power transition.
 */
static int
hda_codec_snapshot(struct hda_codec_inst *hci, struct vm_snapshot_meta *meta)
{
	struct {
		uint8_t channel;
		uint16_t fmt;
		uint8_t stream;
		uint8_t left_gain;
		uint8_t right_gain;
		uint8_t left_mute;
		uint8_t right_mute;
	} candidate[HDA_CODEC_STREAMS_COUNT];
	struct hda_codec_softc *sc;
	struct hda_codec_stream *st;
	uint32_t magic, version;
	uint8_t shape;
	int i, ret;

	if (hci == NULL || hci->priv == NULL || meta == NULL)
		return (EINVAL);
	sc = hci->priv;

	magic = HDA_CODEC_SNAPSHOT_MAGIC;
	version = HDA_CODEC_SNAPSHOT_VERSION;
	shape = hda_codec_snapshot_shape(sc);
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(shape, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    (magic != HDA_CODEC_SNAPSHOT_MAGIC ||
	    version != HDA_CODEC_SNAPSHOT_VERSION ||
	    shape != hda_codec_snapshot_shape(sc))) {
		ret = ENOTSUP;
		goto done;
	}

	for (i = 0; i < HDA_CODEC_STREAMS_COUNT; i++) {
		st = &sc->streams[i];
		candidate[i].channel = st->channel;
		candidate[i].fmt = atomic_load_explicit(&st->fmt,
		    memory_order_relaxed);
		candidate[i].stream = atomic_load_explicit(&st->stream,
		    memory_order_relaxed);
		candidate[i].left_gain = st->left_gain;
		candidate[i].right_gain = st->right_gain;
		candidate[i].left_mute = st->left_mute;
		candidate[i].right_mute = st->right_mute;

		SNAPSHOT_U8_OR_LEAVE(candidate[i].channel, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(candidate[i].fmt, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(candidate[i].stream, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(candidate[i].left_gain, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(candidate[i].right_gain, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(candidate[i].left_mute, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(candidate[i].right_mute, meta, ret, done);
		if (vm_snapshot_is_loading(meta) &&
		    !hda_codec_snapshot_stream_valid(candidate[i].channel,
		    candidate[i].stream, candidate[i].left_gain,
		    candidate[i].right_gain, candidate[i].left_mute,
		    candidate[i].right_mute)) {
			ret = EINVAL;
			goto done;
		}
	}

	if (meta->op == VM_SNAPSHOT_RESTORE) {
		for (i = 0; i < HDA_CODEC_STREAMS_COUNT; i++) {
			st = &sc->streams[i];
			st->channel = candidate[i].channel;
			atomic_store_explicit(&st->fmt, candidate[i].fmt,
			    memory_order_relaxed);
			atomic_store_explicit(&st->stream,
			    candidate[i].stream, memory_order_relaxed);
			st->left_gain = candidate[i].left_gain;
			st->right_gain = candidate[i].right_gain;
			st->left_mute = candidate[i].left_mute;
			st->right_mute = candidate[i].right_mute;
		}
	}
	ret = 0;

done:
	return (ret);
}
#endif	/* BHYVE_SNAPSHOT */

static const struct hda_codec_class hda_codec = {
	.name		= "hda_codec",
	.init		= hda_codec_init,
	.reset		= hda_codec_reset,
	.command	= hda_codec_command,
	.notify		= hda_codec_notify,
#ifdef BHYVE_SNAPSHOT
	.snapshot	= hda_codec_snapshot,
#endif
};
HDA_EMUL_SET(hda_codec);

/*
 * HDA Audio Context module function definitions
 */

static void *
hda_audio_ctxt_thr(void *arg)
{
	struct hda_audio_ctxt *actx = arg;

	DPRINTF("Start Thread: %s", actx->name);

	pthread_mutex_lock(&actx->mtx);
	while (1) {
		while (!actx->run && !actx->shutdown)
			pthread_cond_wait(&actx->cond, &actx->mtx);
		if (actx->shutdown)
			break;
		pthread_mutex_unlock(&actx->mtx);
		actx->do_transfer(actx->priv);
		pthread_mutex_lock(&actx->mtx);
	}
	pthread_mutex_unlock(&actx->mtx);

	return (NULL);
}

static int
hda_audio_ctxt_init(struct hda_audio_ctxt *actx, const char *tname,
    transfer_func_t do_transfer, setup_func_t do_setup, void *priv)
{
	int err;

	if (actx == NULL || tname == NULL || do_transfer == NULL ||
	    do_setup == NULL || priv == NULL)
		return (EINVAL);

	memset(actx, 0, sizeof(*actx));

	actx->run = 0;
	actx->do_transfer = do_transfer;
	actx->do_setup = do_setup;
	actx->priv = priv;
	if (strlen(tname) < sizeof(actx->name))
		memcpy(actx->name, tname, strlen(tname) + 1);
	else
		strcpy(actx->name, "unknown");

	err = pthread_mutex_init(&actx->mtx, NULL);
	if (err != 0)
		return (err);

	err = pthread_cond_init(&actx->cond, NULL);
	if (err != 0) {
		pthread_mutex_destroy(&actx->mtx);
		return (err);
	}

	err = pthread_create(&actx->tid, NULL, hda_audio_ctxt_thr, actx);
	if (err != 0) {
		pthread_cond_destroy(&actx->cond);
		pthread_mutex_destroy(&actx->mtx);
		return (err);
	}

	pthread_set_name_np(actx->tid, tname);

	actx->started = 1;

	return (0);
}

static int
hda_audio_ctxt_start(struct hda_audio_ctxt *actx)
{
	int err = 0;

	if (actx == NULL || !actx->started)
		return (-1);

	pthread_mutex_lock(&actx->mtx);
	/* The stream is supposed to be stopped. */
	if (actx->run || actx->shutdown) {
		pthread_mutex_unlock(&actx->mtx);
		return (-1);
	}
	err = (* actx->do_setup)(actx->priv);
	if (!err) {
		actx->run = 1;
		pthread_cond_signal(&actx->cond);
	}
	pthread_mutex_unlock(&actx->mtx);

	return (err);
}

static int
hda_audio_ctxt_stop(struct hda_audio_ctxt *actx)
{
	if (actx == NULL || !actx->started)
		return (0);
	pthread_mutex_lock(&actx->mtx);
	actx->run = 0;
	pthread_mutex_unlock(&actx->mtx);
	return (0);
}

static void
hda_audio_ctxt_fini(struct hda_audio_ctxt *actx)
{
	if (actx == NULL || !actx->started)
		return;

	pthread_mutex_lock(&actx->mtx);
	actx->run = 0;
	actx->shutdown = 1;
	pthread_cond_signal(&actx->cond);
	pthread_mutex_unlock(&actx->mtx);
	(void)pthread_join(actx->tid, NULL);
	pthread_cond_destroy(&actx->cond);
	pthread_mutex_destroy(&actx->mtx);
	actx->started = 0;
}
