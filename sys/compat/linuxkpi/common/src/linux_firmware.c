/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 The FreeBSD Foundation
 * Copyright (c) 2022 Bjoern A. Zeeb
 *
 * This software was developed by Björn Zeeb under sponsorship from
 * the FreeBSD Foundation.
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
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/firmware.h>
#include <sys/taskqueue.h>

#include <linux/types.h>
#include <linux/device.h>
#include <linux/sched.h>

#include <linux/firmware.h>

#undef firmware

SDT_PROVIDER_DEFINE(linuxkpi_fw);
SDT_PROBE_DEFINE2(linuxkpi_fw, firmware, , request__start,
    "void *", "const char *");
SDT_PROBE_DEFINE4(linuxkpi_fw, firmware, , request__done,
    "void *", "const char *", "int", "size_t");
SDT_PROBE_DEFINE3(linuxkpi_fw, firmware, , callback__start,
    "void *", "const char *", "bool");
SDT_PROBE_DEFINE2(linuxkpi_fw, firmware, , callback__done,
    "void *", "const char *");

MALLOC_DEFINE(M_LKPI_FW, "lkpifw", "LinuxKPI firmware");

struct lkpi_fw_task {
	/* Task and arguments for the "nowait" callback. */
	struct task		fw_task;
	gfp_t			gfp;
	char			*fw_name;
	struct device		*dev;
	linker_file_t		module;
	void			*drv;
	void(*cont)(const struct linuxkpi_firmware *, void *);
};

/* THIS_MODULE is the native linker_file, including for multi-module KLDs. */
static int
lkpi_fw_module_hold(linker_file_t file, void *arg)
{

	if (file != arg)
		return (0);
	/* linker_file_foreach() holds the linker lock. */
	file->refs++;
	return (1);
}

static void
lkpi_fw_module_put(linker_file_t file)
{

	if (file != NULL)
		(void)linker_release_module(NULL, NULL, file);
}

static int
_linuxkpi_request_firmware(const char *fw_name, const struct linuxkpi_firmware **fw,
    struct device *dev, gfp_t gfp __unused, bool warn)
{
	const struct firmware *fbdfw;
	struct linuxkpi_firmware *lfw;
	const char *fwimg;
	char *p;
	uint32_t flags;

	if (fw_name == NULL || fw == NULL || dev == NULL) {
		if (fw != NULL)
			*fw = NULL;
		return (-EINVAL);
	}

	SDT_PROBE2(linuxkpi_fw, firmware, , request__start, dev, fw_name);

	/* Set independent on "warn". To debug, bootverbose is avail. */
	flags = FIRMWARE_GET_NOWARN;

	KASSERT(gfp == GFP_KERNEL, ("%s: gfp %#x\n", __func__, gfp));
	lfw = malloc(sizeof(*lfw), M_LKPI_FW, M_WAITOK | M_ZERO);

	/*
	 * Linux can have a path in the firmware which is hard to replicate
	 * for auto-firmware-module-loading.
	 * On FreeBSD, depending on what people do, the firmware will either
	 * be called "fw", or "dir_fw", or "modname_dir_fw".  The latter the
	 * driver author has to deal with herself (requesting the special name).
	 * We also optionally flatten '/'s and '.'s as some firmware modules do.
	 * We probe in the least-of-work order avoiding memory operations.
	 * It will be preferred to build the firmware .ko in a well matching
	 * way rather than adding more name-mangling-hacks here in the future
	 * (though we could if needed).
	 */
	/* (1) Try the original name. */
	fbdfw = firmware_get_flags(fw_name, flags);
	/* (2) Try any name removed of path, if we have not yet. */
	if (fbdfw == NULL) {
		fwimg = strrchr(fw_name, '/');
		if (fwimg != NULL)
			fwimg++;
		if (fwimg == NULL || *fwimg == '\0')
			fwimg = fw_name;
		if (fwimg != fw_name)
			fbdfw = firmware_get_flags(fwimg, flags);
	}
	/* (3) Flatten '/', '.' and '-' to '_' and try with adjusted name. */
	if (fbdfw == NULL &&
	    (strchr(fw_name, '/') != NULL || strchr(fw_name, '.') != NULL ||
	    strchr(fw_name, '-'))) {
		fwimg = strdup(fw_name, M_LKPI_FW);
		if (fwimg != NULL) {
			while ((p = strchr(fwimg, '/')) != NULL)
				*p = '_';
			fbdfw = firmware_get_flags(fwimg, flags);
			if (fbdfw == NULL) {
				while ((p = strchr(fwimg, '.')) != NULL)
					*p = '_';
				fbdfw = firmware_get_flags(fwimg, flags);
			}
			if (fbdfw == NULL) {
				while ((p = strchr(fwimg, '-')) != NULL)
					*p = '_';
				fbdfw = firmware_get_flags(fwimg, flags);
			}
			free(__DECONST(void *, fwimg), M_LKPI_FW);
		}
	}
	if (fbdfw == NULL) {
		free(lfw, M_LKPI_FW);
		*fw = NULL;
		if (warn)
			device_printf(dev->bsddev, "could not load firmware "
			    "image '%s'\n", fw_name);
		SDT_PROBE4(linuxkpi_fw, firmware, , request__done,
		    dev, fw_name, -ENOENT, 0);
		return (-ENOENT);
	}

	device_printf(dev->bsddev,"successfully loaded firmware image '%s'\n",
	    fw_name);
	lfw->fbdfw = fbdfw;
	lfw->data = (const uint8_t *)fbdfw->data;
	lfw->size = fbdfw->datasize;
	*fw = lfw;
	SDT_PROBE4(linuxkpi_fw, firmware, , request__done,
	    dev, fw_name, 0, lfw->size);
	return (0);
}

static void
lkpi_fw_task(void *ctx, int pending)
{
	struct lkpi_fw_task *lfwt;
	const struct linuxkpi_firmware *fw;
	linker_file_t module;

	KASSERT(ctx != NULL && pending == 1, ("%s: lfwt %p, pending %d\n",
	    __func__, ctx, pending));

	linux_set_current(curthread);
	lfwt = ctx;
	if (lfwt->cont == NULL)
		goto out;

	_linuxkpi_request_firmware(lfwt->fw_name, &fw, lfwt->dev,
	    lfwt->gfp, true);

	/*
	 * Linux seems to run the callback if it cannot find the firmware.
	 * We call it in all cases as it is the only feedback to the requester.
	 */
	SDT_PROBE3(linuxkpi_fw, firmware, , callback__start,
	    lfwt->dev, lfwt->fw_name, (fw != NULL));
	lfwt->cont(fw, lfwt->drv);
	SDT_PROBE2(linuxkpi_fw, firmware, , callback__done,
	    lfwt->dev, lfwt->fw_name);
	/* Do not assume fw is still valid! */

out:
	/* Unbind requested by the callback is safe only after it returns. */
	if (lfwt->dev->bsd_async_put != NULL)
		lfwt->dev->bsd_async_put(lfwt->dev);
	module = lfwt->module;
	put_device(lfwt->dev);
	free(lfwt->fw_name, M_LKPI_FW);
	free(lfwt, M_LKPI_FW);
	lkpi_fw_module_put(module);
}

int
linuxkpi_request_firmware_nowait(struct module *mod, bool _t __unused,
    const char *fw_name, struct device *dev, gfp_t gfp, void *drv,
    void(*cont)(const struct linuxkpi_firmware *, void *))
{
	struct lkpi_fw_task *lfwt;
	int error;

	if (fw_name == NULL || dev == NULL || cont == NULL)
		return (-EINVAL);
	if (mod != NULL && linker_file_foreach(lkpi_fw_module_hold, mod) == 0)
		return (-ENODEV);
	lfwt = malloc(sizeof(*lfwt), M_LKPI_FW, M_WAITOK | M_ZERO);
	lfwt->module = (linker_file_t)mod;
	lfwt->gfp = gfp;
	lfwt->fw_name = strdup(fw_name, M_LKPI_FW);
	lfwt->dev = get_device(dev);
	if (dev->bsd_async_get != NULL) {
		error = dev->bsd_async_get(dev);
		if (error != 0)
			goto fail;
	}
	lfwt->drv = drv;
	lfwt->cont = cont;
	TASK_INIT(&lfwt->fw_task, 0, lkpi_fw_task, lfwt);
	error = taskqueue_enqueue(taskqueue_thread, &lfwt->fw_task);

	if (error == 0)
		return (0);
	if (dev->bsd_async_put != NULL)
		dev->bsd_async_put(dev);
	error = -error;
fail:
	put_device(lfwt->dev);
	free(lfwt->fw_name, M_LKPI_FW);
	free(lfwt, M_LKPI_FW);
	lkpi_fw_module_put((linker_file_t)mod);
	return (error);
}

int
linuxkpi_request_firmware(const struct linuxkpi_firmware **fw,
    const char *fw_name, struct device *dev)
{

	return (_linuxkpi_request_firmware(fw_name, fw, dev, GFP_KERNEL,
	    true));
}

int
linuxkpi_firmware_request_nowarn(const struct linuxkpi_firmware **fw,
    const char *fw_name, struct device *dev)
{

	return (_linuxkpi_request_firmware(fw_name, fw, dev, GFP_KERNEL,
	    false));
}

void
linuxkpi_release_firmware(const struct linuxkpi_firmware *fw)
{

	if (fw == NULL)
		return;

	if (fw->fbdfw)
		firmware_put(fw->fbdfw, FIRMWARE_UNLOAD);
	free(__DECONST(void *, fw), M_LKPI_FW);
}

int
linuxkpi_request_partial_firmware_into_buf(const struct linuxkpi_firmware **fw,
    const char *fw_name, struct device *dev, uint8_t *buf, size_t buflen,
    size_t offset)
{
	const struct linuxkpi_firmware *lfw;
	int error;

	error = linuxkpi_request_firmware(fw, fw_name, dev);
	if (error != 0)
		return (error);

	lfw = *fw;
	if ((offset + buflen) >= lfw->size) {
		linuxkpi_release_firmware(lfw);
		return (-ERANGE);
	}

	memcpy(buf, lfw->data + offset, buflen);

	return (0);
}
