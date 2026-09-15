/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux SDIO drivers over the native CAM SDIO bus. */
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <dev/sdio/sdiob.h>
#include <linux/mmc/sdio_func.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/sched.h>
#include "sdio_if.h"

SDT_PROVIDER_DEFINE(linuxkpi_sdio);
SDT_PROBE_DEFINE1(linuxkpi_sdio, sdio, , host__wait,
    "void *");
SDT_PROBE_DEFINE1(linuxkpi_sdio, sdio, , host__claimed,
    "void *");
SDT_PROBE_DEFINE1(linuxkpi_sdio, sdio, , host__release,
    "void *");
SDT_PROBE_DEFINE3(linuxkpi_sdio, sdio, , irq__poll,
    "void *", "int", "uint8_t");
SDT_PROBE_DEFINE1(linuxkpi_sdio, sdio, , irq__dispatch,
    "void *");
SDT_PROBE_DEFINE2(linuxkpi_sdio, sdio, , attach__start,
    "device_t", "unsigned int");
SDT_PROBE_DEFINE2(linuxkpi_sdio, sdio, , attach__done,
    "device_t", "int");
SDT_PROBE_DEFINE1(linuxkpi_sdio, sdio, , detach__start,
    "device_t");
SDT_PROBE_DEFINE2(linuxkpi_sdio, sdio, , detach__done,
    "device_t", "int");

struct lkpi_sdio_card {
	TAILQ_ENTRY(lkpi_sdio_card) link;
	device_t bus;
	struct device hostdev;
	struct mmc_host host;
	struct mmc_card card;
	struct taskqueue *irq_queue;
	struct timeout_task irq_task;
	struct timeout_task unbind_task;
	bool unbind_scheduled;
	unsigned int users;
	/* Protected by the newbus topology lock, shared by all functions. */
	unsigned int async_users;
	unsigned int probing;
	unsigned int unbind_pending;
	bool detaching;
	bool stopping;
};
struct lkpi_sdio_softc {
	struct lkpi_sdio_card *card;
	struct sdio_func *func;
	struct sdio_driver *driver;
};
/* Newbus topology serialization protects card creation and users. */
static TAILQ_HEAD(, lkpi_sdio_card) lkpi_sdio_cards =
    TAILQ_HEAD_INITIALIZER(lkpi_sdio_cards);
static TAILQ_HEAD(, sdio_driver) lkpi_sdio_drivers =
    TAILQ_HEAD_INITIALIZER(lkpi_sdio_drivers);
static struct taskqueue *lkpi_sdio_unbind_queue;
static unsigned int lkpi_sdio_unbind_jobs;
static void lkpi_sdio_unbind_task(void *, int);

static struct lkpi_sdio_card *
lkpi_sdio_card(struct sdio_func *func)
{

	return (func->card->host->bsd_private);
}

static int
lkpi_sdio_error(int error)
{

	/* Linux drivers distinguish an absent card from ordinary I/O errors. */
	return (error == ENXIO || error == ENODEV ? -ENOMEDIUM : -error);
}

void
linux_sdio_claim_host(struct sdio_func *func)
{

	SDT_PROBE1(linuxkpi_sdio, sdio, , host__wait, func);
	SDIO_CLAIM_HOST(lkpi_sdio_card(func)->bus);
	SDT_PROBE1(linuxkpi_sdio, sdio, , host__claimed, func);
}

void
linux_sdio_release_host(struct sdio_func *func)
{

	SDT_PROBE1(linuxkpi_sdio, sdio, , host__release, func);
	SDIO_RELEASE_HOST(lkpi_sdio_card(func)->bus);
}

static u8
lkpi_sdio_readb(struct sdio_func *func, unsigned int fn, unsigned int addr,
    int *errp)
{
	u8 value = 0xff;
	int error;

	error = SDIO_READ_DIRECT(lkpi_sdio_card(func)->bus, fn, addr, &value);
	if (errp != NULL)
		*errp = lkpi_sdio_error(error);
	return (value);
}

static void
lkpi_sdio_writeb(struct sdio_func *func, unsigned int fn, u8 value,
    unsigned int addr, int *errp)
{
	int error;

	error = SDIO_WRITE_DIRECT(lkpi_sdio_card(func)->bus, fn, addr, value);
	if (errp != NULL)
		*errp = lkpi_sdio_error(error);
}

u8
linux_sdio_readb(struct sdio_func *func, unsigned int addr, int *errp)
{

	return (lkpi_sdio_readb(func, func->num, addr, errp));
}

void
linux_sdio_writeb(struct sdio_func *func, u8 value, unsigned int addr, int *errp)
{

	lkpi_sdio_writeb(func, func->num, value, addr, errp);
}

u8
linux_sdio_f0_readb(struct sdio_func *func, unsigned int addr, int *errp)
{

	return (lkpi_sdio_readb(func, 0, addr, errp));
}

void
linux_sdio_f0_writeb(struct sdio_func *func, u8 value, unsigned int addr,
    int *errp)
{

	if ((addr < 0xf0 || addr > 0xff) &&
	    !(func->card->quirks & MMC_QUIRK_LENIENT_FN0)) {
		if (errp != NULL)
			*errp = -EINVAL;
		return;
	}
	lkpi_sdio_writeb(func, 0, value, addr, errp);
}

static int
lkpi_sdio_transfer(struct sdio_func *func, unsigned int addr, void *data,
    int count, bool write, bool increment)
{
	int error;

	if (count < 0 || (count != 0 && data == NULL))
		return (-EINVAL);
	if (write)
		error = SDIO_WRITE_EXTENDED(lkpi_sdio_card(func)->bus, func->num,
		    addr, count, data, increment);
	else
		error = SDIO_READ_EXTENDED(lkpi_sdio_card(func)->bus, func->num,
		    addr, count, data, increment);
	return (lkpi_sdio_error(error));
}

int
linux_sdio_memcpy_fromio(struct sdio_func *func, void *dst,
    unsigned int addr, int count)
{

	return (lkpi_sdio_transfer(func, addr, dst, count, false, true));
}

int
linux_sdio_memcpy_toio(struct sdio_func *func, unsigned int addr,
    void *src, int count)
{

	return (lkpi_sdio_transfer(func, addr, src, count, true, true));
}

int
linux_sdio_readsb(struct sdio_func *func, void *dst, unsigned int addr, int count)
{

	return (lkpi_sdio_transfer(func, addr, dst, count, false, false));
}

int
linux_sdio_writesb(struct sdio_func *func, unsigned int addr, void *src, int count)
{

	return (lkpi_sdio_transfer(func, addr, src, count, true, false));
}

u16
linux_sdio_readw(struct sdio_func *func, unsigned int addr, int *errp)
{
	u8 bytes[2];
	int error;

	error = linux_sdio_memcpy_fromio(func, bytes, addr, sizeof(bytes));
	if (errp != NULL)
		*errp = error;
	return (error == 0 ? le16dec(bytes) : 0xffff);
}

u32
linux_sdio_readl(struct sdio_func *func, unsigned int addr, int *errp)
{
	u8 bytes[4];
	int error;

	error = linux_sdio_memcpy_fromio(func, bytes, addr, sizeof(bytes));
	if (errp != NULL)
		*errp = error;
	return (error == 0 ? le32dec(bytes) : 0xffffffff);
}

void
linux_sdio_writew(struct sdio_func *func, u16 value, unsigned int addr, int *errp)
{
	u8 bytes[2];
	int error;

	le16enc(bytes, value);
	error = linux_sdio_memcpy_toio(func, addr, bytes, sizeof(bytes));
	if (errp != NULL)
		*errp = error;
}

void
linux_sdio_writel(struct sdio_func *func, u32 value, unsigned int addr, int *errp)
{
	u8 bytes[4];
	int error;

	le32enc(bytes, value);
	error = linux_sdio_memcpy_toio(func, addr, bytes, sizeof(bytes));
	if (errp != NULL)
		*errp = error;
}

int
linux_sdio_enable_func(struct sdio_func *func)
{
	sbintime_t deadline;
	u8 value;
	int error;

	linux_sdio_claim_host(func);
	value = lkpi_sdio_readb(func, 0, SDIO_CCCR_IOEx, &error);
	if (error != 0)
		goto out;
	lkpi_sdio_writeb(func, 0, value | (1U << func->num), SDIO_CCCR_IOEx,
	    &error);
	if (error != 0)
		goto out;
	deadline = sbinuptime() + (sbintime_t)func->enable_timeout * SBT_1MS;
	for (;;) {
		value = lkpi_sdio_readb(func, 0, SDIO_CCCR_IORx, &error);
		if (error != 0 || (value & (1U << func->num)) != 0)
			break;
		if (sbinuptime() >= deadline) {
			error = -ETIMEDOUT;
			break;
		}
		pause_sbt("sdioen", SBT_1MS, 0, C_HARDCLOCK);
	}
out:
	linux_sdio_release_host(func);
	return (error);
}

int
linux_sdio_disable_func(struct sdio_func *func)
{
	u8 value;
	int error;

	linux_sdio_claim_host(func);
	value = lkpi_sdio_readb(func, 0, SDIO_CCCR_IOEx, &error);
	if (error == 0)
		lkpi_sdio_writeb(func, 0, value & ~(1U << func->num),
		    SDIO_CCCR_IOEx, &error);
	linux_sdio_release_host(func);
	return (error);
}

int
linux_sdio_set_block_size(struct sdio_func *func, unsigned int size)
{
	int error;

	if (size == 0)
		size = min(512U, min(func->max_blksize, func->card->host->max_blk_size));
	if (size == 0 || size > UINT16_MAX ||
	    size > func->card->host->max_blk_size)
		return (-EINVAL);
	linux_sdio_claim_host(func);
	error = SDIO_SET_BLOCK_SIZE(lkpi_sdio_card(func)->bus, func->num, size);
	if (error == 0)
		func->cur_blksize = size;
	linux_sdio_release_host(func);
	return (lkpi_sdio_error(error));
}

unsigned int
linux_sdio_align_size(struct sdio_func *func, unsigned int size)
{

	/* Exact-sized transfers are supported; no extra card bytes are needed. */
	(void)func;
	return (size);
}

mmc_pm_flag_t
linux_sdio_get_host_pm_caps(struct sdio_func *func)
{

	return (func->card->host->pm_caps);
}

int
linux_sdio_set_host_pm_flags(struct sdio_func *func, mmc_pm_flag_t flags)
{

	return ((flags & ~func->card->host->pm_caps) != 0 ? -EINVAL : 0);
}

void
linux_mmc_set_data_timeout(struct mmc_data *data, const struct mmc_card *card)
{

	(void)card;
	data->timeout_ns = 1000000000;
	data->timeout_clks = 0;
}

void
linux_mmc_wait_for_req(struct mmc_host *host, struct mmc_request *request)
{
	struct lkpi_sdio_card *card = host->bsd_private;
	struct mmc_command *cmd = request->cmd;
	struct mmc_data *data = request->data;
	struct sdio_func *func;
	struct scatterlist *sg;
	unsigned int fn, addr, length, count, remaining, i;
	void *buffer;
	bool write;
	int error;

	if (cmd == NULL)
		return;
	cmd->error = -EINVAL;
	if (data != NULL) {
		data->error = 0;
		data->bytes_xfered = 0;
	}
	if (cmd->opcode != SD_IO_RW_EXTENDED || request->stop != NULL ||
	    data == NULL || data->blksz == 0 || data->blocks == 0 ||
	    data->blocks > host->max_blk_count ||
	    data->blksz > host->max_blk_size ||
	    data->blksz > host->max_req_size / data->blocks)
		return;
	fn = (cmd->arg >> 28) & 7;
	addr = (cmd->arg >> 9) & 0x1ffff;
	if (fn == 0 || (func = card->card.sdio_func[fn - 1]) == NULL)
		return;
	length = data->blocks * data->blksz;
	count = cmd->arg & 0x1ff;
	if ((cmd->arg & (1U << 27)) != 0) {
		/* Zero is an unbounded block transfer, which is unsupported. */
		if (count == 0 || count != data->blocks ||
		    data->blksz != func->cur_blksize)
			return;
	} else if (data->blocks != 1 || length != (count != 0 ? count : 512))
		return;
	write = (cmd->arg & (1U << 31)) != 0;
	if (data->sg == NULL || data->sg_len == 0 ||
	    data->sg_len > host->max_segs ||
	    data->flags != (write ? MMC_DATA_WRITE : MMC_DATA_READ))
		return;
	/* Validate read destinations before consuming bytes from a card FIFO. */
	remaining = length;
	for_each_sg(data->sg, sg, data->sg_len, i) {
		if (sg == NULL || sg->length > host->max_seg_size)
			return;
		remaining -= min(remaining, sg->length);
	}
	if (remaining != 0)
		return;
	buffer = kmalloc(length, GFP_KERNEL);
	if (buffer == NULL) {
		cmd->error = -ENOMEM;
		return;
	}
	if (write && sg_pcopy_to_buffer(data->sg, data->sg_len, buffer,
	    length, 0) != length) {
		kfree(buffer);
		return;
	}
	error = lkpi_sdio_transfer(func, addr, buffer, length, write,
	    (cmd->arg & (1U << 26)) != 0);
	if (error == 0 && !write && sg_copy_from_buffer(data->sg, data->sg_len,
	    buffer, length) != length)
		error = -EINVAL;
	cmd->error = error;
	if (error == 0)
		data->bytes_xfered = length;
	kfree(buffer);
}

int
linux_mmc_hw_reset(struct mmc_card *card)
{

	/* Native CAM does not expose a card power-cycle operation yet. */
	(void)card;
	return (-EOPNOTSUPP);
}

/* Poll CCCR pending bits until native SDIO interrupt delivery is available. */
static void
lkpi_sdio_irq_task(void *arg, int pending __unused)
{
	struct lkpi_sdio_card *card = arg;
	struct sdio_func *func;
	u8 status;
	bool armed = false;
	int error;

	linux_set_current(curthread);
	SDIO_CLAIM_HOST(card->bus);
	if (!card->stopping) {
		error = SDIO_READ_DIRECT(card->bus, 0, SDIO_CCCR_INTx, &status);
		SDT_PROBE3(linuxkpi_sdio, sdio, , irq__poll,
		    card->bus, error, (error == 0 ? status : 0));
		for (unsigned int i = 0; i < nitems(card->card.sdio_func); i++) {
			func = card->card.sdio_func[i];
			if (func == NULL || func->irq_handler == NULL)
				continue;
			armed = true;
			if (error == 0 && (status & (1U << func->num)) != 0) {
				SDT_PROBE1(linuxkpi_sdio, sdio, , irq__dispatch, func);
				func->irq_handler(func);
			}
		}
		if (armed)
			taskqueue_enqueue_timeout(card->irq_queue, &card->irq_task,
			    max(1, hz / 100));
	}
	SDIO_RELEASE_HOST(card->bus);
}

int
linux_sdio_claim_irq(struct sdio_func *func, sdio_irq_handler_t *handler)
{
	struct lkpi_sdio_card *card = lkpi_sdio_card(func);
	u8 enabled;
	int error;

	linux_sdio_claim_host(func);
	if (handler == NULL || func->irq_handler != NULL || card->stopping) {
		error = -EINVAL;
		goto out;
	}
	enabled = lkpi_sdio_readb(func, 0, SDIO_CCCR_IENx, &error);
	if (error != 0)
		goto out;
	lkpi_sdio_writeb(func, 0, enabled | 1U | (1U << func->num),
	    SDIO_CCCR_IENx, &error);
	if (error == 0) {
		func->irq_handler = handler;
		taskqueue_enqueue_timeout(card->irq_queue, &card->irq_task, 1);
	}
out:
	linux_sdio_release_host(func);
	return (error);
}

int
linux_sdio_release_irq(struct sdio_func *func)
{
	u8 enabled;
	int error;

	linux_sdio_claim_host(func);
	/* Clear the callback even if the card has stopped responding. */
	func->irq_handler = NULL;
	enabled = lkpi_sdio_readb(func, 0, SDIO_CCCR_IENx, &error);
	if (error == 0) {
		enabled &= ~(1U << func->num);
		if ((enabled & ~1U) == 0)
			enabled = 0;
		lkpi_sdio_writeb(func, 0, enabled, SDIO_CCCR_IENx, &error);
	}
	linux_sdio_release_host(func);
	return (error);
}

/* Caller holds the topology lock and a Linux reference to the card. */
static void
lkpi_sdio_unbind_pending(struct lkpi_sdio_card *card)
{
	struct sdio_func *func;
	int error;

	bus_topo_assert();
	if (card->async_users != 0 || card->probing != 0 || card->detaching)
		return;
	/* brcmfmac tears down F2 interrupts before F1 frees shared state. */
	for (int i = nitems(card->card.sdio_func) - 1; i >= 0; i--) {
		if (card->stopping)
			break;
		if ((card->unbind_pending & (1U << i)) == 0)
			continue;
		func = card->card.sdio_func[i];
		card->unbind_pending &= ~(1U << i);
		if (func == NULL || func->dev.driver == NULL)
			continue;
		error = device_detach(func->dev.bsddev);
		if (error != 0) {
			card->unbind_pending |= 1U << i;
			if (error != EBUSY)
				device_printf(func->dev.bsddev,
				    "could not unbind SDIO driver: %d\n", error);
			break;
		}
	}
}

/* The queued job owns a card reference until its last retry completes. */
static void
lkpi_sdio_schedule_unbind(struct lkpi_sdio_card *card)
{

	bus_topo_assert();
	if (card->stopping || card->unbind_pending == 0 || card->unbind_scheduled)
		return;
	get_device(&card->card.dev);
	card->unbind_scheduled = true;
	lkpi_sdio_unbind_jobs++;
	taskqueue_enqueue_timeout(lkpi_sdio_unbind_queue, &card->unbind_task, 1);
}

static void
lkpi_sdio_unbind_task(void *arg, int pending __unused)
{
	struct lkpi_sdio_card *card = arg;

	linux_set_current(curthread);
	/* The timer that queued us may still be returning on another CPU. */
	callout_drain(&card->unbind_task.c);
	bus_topo_lock();
	if (!card->stopping)
		lkpi_sdio_unbind_pending(card);
	if (!card->stopping && card->unbind_pending != 0) {
		/* Attach or an external device user may still prevent detaching. */
		taskqueue_enqueue_timeout(lkpi_sdio_unbind_queue,
		    &card->unbind_task, max(1, hz / 10));
	} else {
		card->unbind_scheduled = false;
		lkpi_sdio_unbind_jobs--;
		put_device(&card->card.dev);
	}
	bus_topo_unlock();
}

static int
lkpi_sdio_async_get(struct device *dev)
{
	struct lkpi_sdio_card *card = lkpi_sdio_card(dev_to_sdio_func(dev));
	int error = 0;

	bus_topo_lock();
	if (card->stopping || card->detaching || card->unbind_pending != 0 ||
	    dev->driver == NULL ||
	    container_of(dev->driver, struct sdio_driver, drv)->bsd_unloading)
		error = -ENODEV;
	else
		card->async_users++;
	bus_topo_unlock();
	return (error);
}

static void
lkpi_sdio_async_put(struct device *dev)
{
	struct lkpi_sdio_card *card = lkpi_sdio_card(dev_to_sdio_func(dev));

	bus_topo_lock();
	KASSERT(card->async_users != 0, ("SDIO async reference underflow"));
	card->async_users--;
	lkpi_sdio_schedule_unbind(card);
	bus_topo_unlock();
}

static void
lkpi_sdio_release_driver(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct lkpi_sdio_card *card = lkpi_sdio_card(func);

	get_device(&card->card.dev);
	bus_topo_lock();
	if (dev->driver != NULL)
		card->unbind_pending |= 1U << (func->num - 1);
	/* Never unbind inline: even an inline firmware failure can be in probe. */
	lkpi_sdio_schedule_unbind(card);
	bus_topo_unlock();
	put_device(&card->card.dev);
}

static void
lkpi_sdio_host_release(struct device *dev)
{

	kfree(container_of(dev, struct lkpi_sdio_card, hostdev));
}

static void
lkpi_sdio_card_release(struct device *dev)
{

	put_device(dev->parent);
}

static void
lkpi_sdio_func_release(struct device *dev)
{
	struct device *parent = dev->parent;

	of_node_put(dev->of_node);
	kfree(container_of(dev, struct sdio_func, dev));
	put_device(parent);
}

static void
lkpi_sdio_device_init(struct device *dev, device_t bsddev,
    struct device *parent, void (*release)(struct device *))
{

	dev->bsddev = bsddev;
	dev->parent = parent;
	dev->release = release;
	dev->irq = LINUX_IRQ_INVALID;
	kobject_init(&dev->kobj, &linux_dev_ktype);
	spin_lock_init(&dev->devres_lock);
	INIT_LIST_HEAD(&dev->devres_head);
	INIT_LIST_HEAD(&dev->irqents);
	dev_set_name(dev, "%s", device_get_nameunit(bsddev));
}

static void
lkpi_sdio_card_destroy(struct lkpi_sdio_card *card)
{
	struct sdio_func *func;

	SDIO_CLAIM_HOST(card->bus);
	card->stopping = true;
	SDIO_RELEASE_HOST(card->bus);
	if (card->irq_queue != NULL) {
		taskqueue_drain_timeout(card->irq_queue, &card->irq_task);
		taskqueue_free(card->irq_queue);
	}
	for (unsigned int i = 0; i < nitems(card->card.sdio_func); i++) {
		func = card->card.sdio_func[i];
		if (func != NULL)
			put_device(&func->dev);
	}
	put_device(&card->card.dev);
}

static struct lkpi_sdio_card *
lkpi_sdio_card_get(device_t bus)
{
	struct lkpi_sdio_card *card;
	struct sdio_func *func;
	device_t *children;
	unsigned int fn;
	int count, error;

	TAILQ_FOREACH(card, &lkpi_sdio_cards, link) {
		if (card->bus == bus) {
			card->users++;
			return (card);
		}
	}
	error = device_get_children(bus, &children, &count);
	if (error != 0)
		return (NULL);
	card = kzalloc(sizeof(*card), GFP_KERNEL);
	if (card == NULL) {
		free(children, M_TEMP);
		return (NULL);
	}
	card->bus = bus;
	card->users = 1;
	lkpi_sdio_device_init(&card->hostdev, device_get_parent(bus),
	    &linux_root_device, lkpi_sdio_host_release);
	lkpi_sdio_device_init(&card->card.dev, bus, &card->hostdev,
	    lkpi_sdio_card_release);
	TIMEOUT_TASK_INIT(lkpi_sdio_unbind_queue, &card->unbind_task, 0,
	    lkpi_sdio_unbind_task, card);
	card->card.host = &card->host;
	card->host.parent = &card->hostdev;
	card->host.bsd_private = card;
	/* Start with the linear transfer path; do not advertise SG or PM. */
	card->host.max_segs = 1;
	card->host.max_req_size = maxphys;
	card->host.max_seg_size = maxphys;
	card->host.max_blk_size = 512;
	card->host.max_blk_count = min(511UL, maxphys / 512);
	for (int i = 0; i < count; i++) {
		fn = sdio_get_funcnum(children[i]);
		if (fn == 0 || fn > nitems(card->card.sdio_func))
			continue;
		func = kzalloc(sizeof(*func), GFP_KERNEL);
		if (func == NULL)
			goto fail;
		func->card = &card->card;
		func->num = fn;
		func->class = sdio_get_class(children[i]);
		func->vendor = sdio_get_vendor(children[i]);
		func->device = sdio_get_device(children[i]);
		func->max_blksize = sdio_get_max_blksize(children[i]);
		func->cur_blksize = sdio_get_cur_blksize(children[i]);
		func->enable_timeout = 1000;
		get_device(&card->card.dev);
		lkpi_sdio_device_init(&func->dev, children[i], &card->card.dev,
		    lkpi_sdio_func_release);
		func->dev.bsd_async_get = lkpi_sdio_async_get;
		func->dev.bsd_async_put = lkpi_sdio_async_put;
		func->dev.bsd_release_driver = lkpi_sdio_release_driver;
		func->dev.of_node = linux_of_get_sdio_node(device_get_parent(bus), fn);
		card->card.sdio_func[fn - 1] = func;
	}
	free(children, M_TEMP);
	card->irq_queue = taskqueue_create("lkpi_sdio", M_WAITOK,
	    taskqueue_thread_enqueue, &card->irq_queue);
	TIMEOUT_TASK_INIT(card->irq_queue, &card->irq_task, 0,
	    lkpi_sdio_irq_task, card);
	error = taskqueue_start_threads(&card->irq_queue, 1, PWAIT, "lkpi_sdio");
	if (error != 0) {
		lkpi_sdio_card_destroy(card);
		return (NULL);
	}
	TAILQ_INSERT_HEAD(&lkpi_sdio_cards, card, link);
	return (card);
fail:
	free(children, M_TEMP);
	lkpi_sdio_card_destroy(card);
	return (NULL);
}

static void
lkpi_sdio_card_put(struct lkpi_sdio_card *card)
{

	if (--card->users != 0)
		return;
	TAILQ_REMOVE(&lkpi_sdio_cards, card, link);
	lkpi_sdio_card_destroy(card);
}

static const struct sdio_device_id *
lkpi_sdio_match(device_t dev, struct sdio_driver *driver)
{
	const struct sdio_device_id *id;

	if (sdio_get_funcnum(dev) == 0 || driver->id_table == NULL)
		return (NULL);
	for (id = driver->id_table; id->class || id->vendor || id->device; id++) {
		if ((id->class == SDIO_ANY_ID || id->class == sdio_get_class(dev)) &&
		    (id->vendor == SDIO_ANY_ID || id->vendor == sdio_get_vendor(dev)) &&
		    (id->device == SDIO_ANY_ID || id->device == sdio_get_device(dev)))
			return (id);
	}
	return (NULL);
}

static int
lkpi_sdio_probe(device_t dev)
{
	struct sdio_driver *driver = container_of(device_get_driver(dev),
	    struct sdio_driver, bsd_driver);

	if (driver->bsd_unloading || lkpi_sdio_match(dev, driver) == NULL)
		return (ENXIO);
	device_set_desc(dev, driver->name);
	return (BUS_PROBE_DEFAULT);
}

static int
lkpi_sdio_attach(device_t dev)
{
	struct lkpi_sdio_softc *sc = device_get_softc(dev);
	unsigned int fn = sdio_get_funcnum(dev);
	int error;

	SDT_PROBE2(linuxkpi_sdio, sdio, , attach__start, dev, fn);
	linux_set_current(curthread);
	sc->driver = container_of(device_get_driver(dev), struct sdio_driver,
	    bsd_driver);
	if (sc->driver->bsd_unloading) {
		SDT_PROBE2(linuxkpi_sdio, sdio, , attach__done, dev, EBUSY);
		return (EBUSY);
	}
	sc->card = lkpi_sdio_card_get(device_get_parent(dev));
	if (sc->card == NULL) {
		SDT_PROBE2(linuxkpi_sdio, sdio, , attach__done, dev, ENOMEM);
		return (ENOMEM);
	}
	/*
	 * Bound the function number before indexing (SDIO allows 1..7).  probe
	 * only rejects fn == 0, and a function slot may be unpopulated, so guard
	 * against an out-of-bounds index and a NULL func here as card_get does.
	 */
	if (fn == 0 || fn > nitems(sc->card->card.sdio_func) ||
	    sc->card->card.sdio_func[fn - 1] == NULL) {
		lkpi_sdio_card_put(sc->card);
		sc->card = NULL;
		SDT_PROBE2(linuxkpi_sdio, sdio, , attach__done, dev, ENXIO);
		return (ENXIO);
	}
	sc->func = sc->card->card.sdio_func[fn - 1];
	sc->func->dev.driver = &sc->driver->drv;
	sc->card->probing++;
	error = sc->driver->probe(sc->func, lkpi_sdio_match(dev, sc->driver));
	sc->card->probing--;
	if (error != 0) {
		linux_sdio_release_irq(sc->func);
		lkpi_devres_release_free_list(&sc->func->dev);
		sc->func->dev.driver = NULL;
		lkpi_sdio_card_put(sc->card);
		sc->card = NULL;
		sc->func = NULL;
	}
	SDT_PROBE2(linuxkpi_sdio, sdio, , attach__done, dev, -error);
	return (-error);
}

static int
lkpi_sdio_detach(device_t dev)
{
	struct lkpi_sdio_softc *sc = device_get_softc(dev);

	SDT_PROBE1(linuxkpi_sdio, sdio, , detach__start, dev);
	linux_set_current(curthread);
	/* References to device objects alone do not protect driver-private state. */
	if (sc->card->async_users != 0 || sc->card->probing != 0 ||
	    sc->card->detaching) {
		SDT_PROBE2(linuxkpi_sdio, sdio, , detach__done, dev, EBUSY);
		return (EBUSY);
	}
	sc->card->detaching = true;
	if (sc->driver->remove != NULL)
		sc->driver->remove(sc->func);
	linux_sdio_release_irq(sc->func);
	lkpi_devres_release_free_list(&sc->func->dev);
	sc->func->dev.driver = NULL;
	sc->card->detaching = false;
	lkpi_sdio_card_put(sc->card);
	sc->card = NULL;
	sc->func = NULL;
	SDT_PROBE2(linuxkpi_sdio, sdio, , detach__done, dev, 0);
	return (0);
}

static device_method_t lkpi_sdio_methods[] = {
	DEVMETHOD(device_probe, lkpi_sdio_probe),
	DEVMETHOD(device_attach, lkpi_sdio_attach),
	DEVMETHOD(device_detach, lkpi_sdio_detach),
	DEVMETHOD_END
};

int
linux_sdio_register_driver(struct sdio_driver *driver)
{
	devclass_t bus;
	int error;

	if (driver->probe == NULL || driver->name == NULL)
		return (-EINVAL);
	linux_set_current(curthread);
	bus_topo_lock();
	if (driver->bsd_registered) {
		bus_topo_unlock();
		return (-EEXIST);
	}
	bus = devclass_create(SDIOB_NAME_S);
	driver->bsd_unloading = false;
	driver->bsd_registered = true;
	TAILQ_INSERT_TAIL(&lkpi_sdio_drivers, driver, bsd_link);
	driver->bsd_driver.name = driver->name;
	driver->bsd_driver.methods = lkpi_sdio_methods;
	driver->bsd_driver.size = sizeof(struct lkpi_sdio_softc);
	error = devclass_add_driver(bus, &driver->bsd_driver, BUS_PASS_DEFAULT,
	    &driver->bsd_class);
	if (error != 0) {
		TAILQ_REMOVE(&lkpi_sdio_drivers, driver, bsd_link);
		driver->bsd_registered = false;
	}
	bus_topo_unlock();
	return (-error);
}

/* Must run before SYSUNINIT: only a module event can veto unloading. */
static int
lkpi_sdio_driver_busy(struct sdio_driver *driver)
{
	struct lkpi_sdio_card *card;
	struct sdio_func *func;

	bus_topo_assert();
	if (lkpi_sdio_unbind_jobs != 0 || driver->bsd_unloading)
		return (EBUSY);
	TAILQ_FOREACH(card, &lkpi_sdio_cards, link) {
		for (unsigned int i = 0; i < nitems(card->card.sdio_func); i++) {
			func = card->card.sdio_func[i];
			if (func != NULL && func->dev.driver == &driver->drv &&
			    (card->async_users != 0 || card->probing != 0 || card->detaching))
				return (EBUSY);
		}
	}
	return (0);
}

static int
lkpi_sdio_delete_driver(struct sdio_driver *driver)
{
	devclass_t bus;
	int error;

	bus_topo_assert();
	if (!driver->bsd_registered)
		return (0);
	error = lkpi_sdio_driver_busy(driver);
	if (error != 0)
		return (error);
	driver->bsd_unloading = true;
	bus = devclass_find(SDIOB_NAME_S);
	error = bus != NULL ? devclass_delete_driver(bus, &driver->bsd_driver) : ENXIO;
	if (error == 0) {
		TAILQ_REMOVE(&lkpi_sdio_drivers, driver, bsd_link);
		driver->bsd_registered = false;
	} else
		driver->bsd_unloading = false;
	return (error);
}

int
linux_sdio_module_event(module_t module __unused, int event, void *table)
{
	struct sdio_driver *driver;
	int error = 0;

	if (event == MOD_LOAD || event == MOD_SHUTDOWN)
		return (0);
	if (event != MOD_QUIESCE && event != MOD_UNLOAD)
		return (EOPNOTSUPP);
	linux_set_current(curthread);
	bus_topo_lock();
	TAILQ_FOREACH(driver, &lkpi_sdio_drivers, bsd_link) {
		if (driver->id_table != table)
			continue;
		error = event == MOD_QUIESCE ? lkpi_sdio_driver_busy(driver) :
		    lkpi_sdio_delete_driver(driver);
		break;
	}
	bus_topo_unlock();
	return (error);
}

void
linux_sdio_unregister_driver(struct sdio_driver *driver)
{
	int error;

	linux_set_current(curthread);
	bus_topo_lock();
	error = lkpi_sdio_delete_driver(driver);
	bus_topo_unlock();
	if (error != 0)
		printf("%s: SDIO driver remains registered: %d\n", driver->name, error);
}

static int
lkpi_sdio_modevent(module_t module __unused, int event, void *arg __unused)
{
	int error;

	switch (event) {
	case MOD_LOAD:
		lkpi_sdio_unbind_queue = taskqueue_create("sdio_unbind", M_WAITOK,
		    taskqueue_thread_enqueue, &lkpi_sdio_unbind_queue);
		error = taskqueue_start_threads(&lkpi_sdio_unbind_queue, 1, PWAIT,
		    "sdio_unbind");
		if (error != 0) {
			taskqueue_free(lkpi_sdio_unbind_queue);
			lkpi_sdio_unbind_queue = NULL;
		}
		return (error);
	case MOD_QUIESCE:
	case MOD_UNLOAD:
		bus_topo_lock();
		error = !TAILQ_EMPTY(&lkpi_sdio_drivers) || lkpi_sdio_unbind_jobs != 0 ?
		    EBUSY : 0;
		bus_topo_unlock();
		if (error == 0 && event == MOD_UNLOAD) {
			/* Wait for the final worker to return before unloading its code. */
			taskqueue_free(lkpi_sdio_unbind_queue);
			lkpi_sdio_unbind_queue = NULL;
		}
		return (error);
	case MOD_SHUTDOWN:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t lkpi_sdio_mod = {
	"linuxkpi_sdio", lkpi_sdio_modevent, NULL
};
DECLARE_MODULE(linuxkpi_sdio, lkpi_sdio_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(linuxkpi_sdio, 1);
MODULE_DEPEND(linuxkpi_sdio, linuxkpi, 1, 1, 1);
MODULE_DEPEND(linuxkpi_sdio, sdiob, 1, 1, 1);
