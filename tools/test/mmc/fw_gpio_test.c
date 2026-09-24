/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RPI_FW_GPIO_PINS 8
#define RPI_FW_GPIO_BASE 128
#define BCM2835_FIRMWARE_TAG_GET_GPIO_STATE 0x00030041
#define bzero(p, n) memset((p), 0, (n))
struct gpio_pin { uint32_t gp_pin; };
struct rpi_fw_gpio_softc {
    void *sc_firmware;
    struct gpio_pin sc_gpio_pins[RPI_FW_GPIO_PINS];
};
typedef struct rpi_fw_gpio_softc *device_t;
#define device_get_softc(dev) (dev)
union msg_get_gpio_state {
    struct { uint32_t gpio, state; } req, resp;
};
static int locked, calls, error;
static uint32_t returned_gpio, returned_state, requested_pin;
#define RPI_FW_GPIO_LOCK(sc) do { (void)(sc); assert(!locked); locked = 1; } while (0)
#define RPI_FW_GPIO_UNLOCK(sc) do { (void)(sc); assert(locked); locked = 0; } while (0)
static int
bcm2835_firmware_property(void *firmware, uint32_t tag, void *data, size_t size)
{
    union msg_get_gpio_state *state = data;
    (void)firmware;
    assert(locked && tag == BCM2835_FIRMWARE_TAG_GET_GPIO_STATE);
    assert(size == sizeof(*state));
    assert(state->req.gpio == RPI_FW_GPIO_BASE + requested_pin);
    assert(state->req.state == 0);
    calls++;
    state->resp.gpio = returned_gpio;
    state->resp.state = returned_state;
    return error;
}
#include "power_functions.h"
int
main(void)
{
    struct rpi_fw_gpio_softc sc = {0};
    unsigned value;
    for (unsigned i = 0; i < RPI_FW_GPIO_PINS; i++) sc.sc_gpio_pins[i].gp_pin = i;
    requested_pin = 1; /* Pi 4 WL_ON. */
    for (unsigned raw = 0; raw <= 2; raw++) {
        returned_state = raw;
        value = 99;
        assert(rpi_fw_gpio_pin_get(&sc, 1, &value) == 0);
        assert(value == (raw != 0) && !locked);
    }
    value = 99;
    error = EIO;
    assert(rpi_fw_gpio_pin_get(&sc, 1, &value) == EIO);
    assert(value == 99 && !locked);
    error = 0;
    returned_gpio = 129; /* Firmware did not acknowledge the requested pin. */
    assert(rpi_fw_gpio_pin_get(&sc, 1, &value) == EINVAL);
    assert(value == 99 && !locked);
    int before = calls;
    assert(rpi_fw_gpio_pin_get(&sc, 8, &value) == EINVAL);
    assert(calls == before && value == 99 && !locked);
    puts("PASS: firmware GPIO state polarity, normalization and read failures");
    return 0;
}
