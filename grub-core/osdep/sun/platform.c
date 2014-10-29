/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/util/install.h>
#include <libdevinfo.h>
#include <string.h>

/* assuming only 64bit UEFI platform. */
const char *
grub_install_get_default_x86_platform (void)
{ 
	di_node_t root;
	di_prop_t prop;
	const char *bios_plat = "i386-pc";
	const char *efi_plat = "x86_64-efi";
	const char *ret = bios_plat;

	if ((root = di_init("/", DINFOPROP)) == DI_NODE_NIL) {
		return (ret);
	}

	prop = DI_PROP_NIL;
	while ((prop = di_prop_hw_next(root, prop)) != DI_PROP_NIL) {
		char *name = di_prop_name(prop);

		if (strncmp(name, "efi-systab", 10) == 0) {
			ret = efi_plat;
			break;
		}
	}

	di_fini(root);
	return (ret);
}

