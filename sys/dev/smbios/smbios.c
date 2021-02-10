/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003 Matthew N. Dodd <winter@jurai.net>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#include <sys/module.h>
#include <sys/bus.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <machine/md_var.h>
#if defined(__amd64__) || defined(__i386__)
#include <machine/pc/bios.h>
#endif
#include <dev/smbios/smbios.h>

static struct smbios_softc *smbios;

/*
 * System Management BIOS Reference Specification, v2.4 Final
 * http://www.dmtf.org/standards/published_documents/DSP0134.pdf
 */

struct smbios_softc {
	device_t		dev;
	struct resource *	res;
	int			rid;

	union {
		struct smbios_eps *	eps;
		struct smbios3_eps *	eps3;
	};
	bool eps_64bit;
};

#define	RES2EPS(res)	((struct smbios_eps *)rman_get_virtual(res))
#define	RES2EPS3(res)	((struct smbios3_eps *)rman_get_virtual(res))

static devclass_t	smbios_devclass;

static void	smbios_identify	(driver_t *, device_t);
static int	smbios_probe	(device_t);
static int	smbios_attach	(device_t);
static int	smbios_detach	(device_t);
static int	smbios_modevent	(module_t, int, void *);

static bool	smbios_eps_64bit(void *);
static int	smbios_cksum	(void *);

static void
smbios_identify (driver_t *driver, device_t parent)
{
	struct smbios3_eps *eps3;
	struct smbios_eps *eps;
	device_t child;
	vm_paddr_t addr;
	int length;
	int rid;
	bool eps_64bit;

	if (!device_is_alive(parent))
		return;

	if (resource_long_value("smbios3", 0, "mem", &addr) != 0) {
#if defined(__amd64__) || defined(__i386__)
		addr = bios_sigsearch(SMBIOS_START, SMBIOS3_SIG, SMBIOS3_LEN,
		    SMBIOS_STEP, SMBIOS_OFF);
#else
		addr = 0;
#endif
	}

	if (addr != 0) {
		eps_64bit = true;
	} else {
		eps_64bit = false;
		if (resource_long_value("smbios", 0, "mem", &addr) != 0) {
#if defined(__amd64__) || defined(__i386__)
			addr = bios_sigsearch(SMBIOS_START, SMBIOS_SIG, SMBIOS_LEN,
			    SMBIOS_STEP, SMBIOS_OFF);
#else
			addr = 0;
#endif
		}
	}

	if (addr != 0) {
		if (eps_64bit) {
			eps3 = pmap_mapbios(addr, 0x18);
			length = eps3->length;
		} else {
			eps = pmap_mapbios(addr, 0x1f);
			length = eps->length;
		}
		rid = 0;

		if (!eps_64bit && length != 0x1f) {
			u_int8_t major, minor;

			major = eps->major_version;
			minor = eps->minor_version;

			/* SMBIOS v2.1 implementation might use 0x1e. */
			if (length == 0x1e && major == 2 && minor == 1)
				length = 0x1f;
			else
				return;
		}

		child = BUS_ADD_CHILD(parent, 5, "smbios", -1);
		device_set_driver(child, driver);
		bus_set_resource(child, SYS_RES_MEMORY, rid, addr, length);
		device_set_desc(child, "System Management BIOS");

		if (eps_64bit)
			pmap_unmapbios((vm_offset_t)eps3, 0x18);
		else
			pmap_unmapbios((vm_offset_t)eps, 0x1f);
	}

	return;
}

static int
smbios_probe (device_t dev)
{
	struct resource *res;
	int rid;
	int error;

	error = 0;
	rid = 0;
	res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid, RF_ACTIVE);
	if (res == NULL) {
		device_printf(dev, "Unable to allocate memory resource.\n");
		error = ENOMEM;
		goto bad;
	}

	if (smbios_cksum(rman_get_virtual(res))) {
		device_printf(dev, "SMBIOS checksum failed.\n");
		error = ENXIO;
		goto bad;
	}

bad:
	if (res)
		bus_release_resource(dev, SYS_RES_MEMORY, rid, res);
	return (error);
}

static int
smbios_attach (device_t dev)
{
	struct smbios_softc *sc;
	int error;

	sc = device_get_softc(dev);
	error = 0;

	sc->dev = dev;
	sc->rid = 0;
	sc->res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->rid,
		RF_ACTIVE);
	if (sc->res == NULL) {
		device_printf(dev, "Unable to allocate memory resource.\n");
		error = ENOMEM;
		goto bad;
	}
	sc->eps_64bit = smbios_eps_64bit(rman_get_virtual(sc->res));

	if (sc->eps_64bit) {
		sc->eps3 = RES2EPS3(sc->res);
		device_printf(dev, "Version: %u.%u",
		    sc->eps3->major_version, sc->eps3->minor_version);
	} else {
		sc->eps = RES2EPS(sc->res);
		device_printf(dev, "Version: %u.%u",
		    sc->eps->major_version, sc->eps->minor_version);
		if (bcd2bin(sc->eps->BCD_revision))
			printf(", BCD Revision: %u.%u",
				bcd2bin(sc->eps->BCD_revision >> 4),
				bcd2bin(sc->eps->BCD_revision & 0x0f));
	}
	printf("\n");

	smbios = sc;
	return (0);
bad:
	if (sc->res)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->rid, sc->res);
	return (error);
}

static int
smbios_detach (device_t dev)
{
	struct smbios_softc *sc;

	smbios = NULL;
	sc = device_get_softc(dev);

	if (sc->res)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->rid, sc->res);

	return (0);
}

int
smbios_get_structure_table(vm_paddr_t *table, vm_size_t *size)
{

	if (smbios == NULL)
		return (ENXIO);
	if (smbios->eps_64bit) {
		*table = smbios->eps3->structure_table_address;
		*size = smbios->eps3->structure_table_max_size;
	} else {
		*table = smbios->eps->structure_table_address;
		*size = smbios->eps->structure_table_length;
	}
	return (0);
}


static int
smbios_modevent (mod, what, arg)
        module_t        mod;
        int             what;
        void *          arg;
{
	device_t *	devs;
	int		count;
	int		i;

	switch (what) {
	case MOD_LOAD:
		break;
	case MOD_UNLOAD:
		devclass_get_devices(smbios_devclass, &devs, &count);
		for (i = 0; i < count; i++) {
			device_delete_child(device_get_parent(devs[i]), devs[i]);
		}
		free(devs, M_TEMP);
		break;
	default:
		break;
	}

	return (0);
}

static device_method_t smbios_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,      smbios_identify),
	DEVMETHOD(device_probe,         smbios_probe),
	DEVMETHOD(device_attach,        smbios_attach),
	DEVMETHOD(device_detach,        smbios_detach),
	{ 0, 0 }
};

static driver_t smbios_driver = {
	"smbios",
	smbios_methods,
	sizeof(struct smbios_softc),
};

DRIVER_MODULE(smbios, nexus, smbios_driver, smbios_devclass, smbios_modevent, 0);
MODULE_VERSION(smbios, 1);

static bool
smbios_eps_64bit (void *v)
{
	struct smbios3_eps *e;

	e = (struct smbios3_eps *)v;
	return (memcmp(e->anchor_string, SMBIOS3_SIG, SMBIOS3_LEN) == 0);
}

static int
smbios_cksum (void *v)
{
	struct smbios3_eps *eps3;
	struct smbios_eps *eps;
	u_int8_t *ptr;
	u_int8_t cksum;
	u_int8_t length;
	int i;

	if (smbios_eps_64bit(v)) {
		eps3 = (struct smbios3_eps *)v;
		length = eps3->length;
	} else {
		eps = (struct smbios_eps *)v;
		length = eps->length;
	}
	ptr = (u_int8_t *)v;
	cksum = 0;
	for (i = 0; i < length; i++) {
		cksum += ptr[i];
	}

	return (cksum);
}
