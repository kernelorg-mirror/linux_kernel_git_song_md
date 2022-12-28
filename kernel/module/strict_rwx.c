// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module strict rwx
 *
 * Copyright (C) 2015 Rusty Russell
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include "internal.h"

bool module_check_misalignment(const struct module *mod)
{
	enum mod_mem_type type;

	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		return false;

	for_each_mod_mem_type(type) {
		if (WARN_ON(!PAGE_ALIGNED(mod->mod_mem[type].base)))
			return true;
	}
	return false;
}

static void module_set_memory(
	const struct module *mod, enum mod_mem_type type,
	int (*set_memory)(unsigned long start, int num_pages))
{
	const struct module_memory *mod_mem = &mod->mod_mem[type];

	set_vm_flush_reset_perms(mod_mem->base);
	set_memory((unsigned long)mod_mem->base, mod_mem->size >> PAGE_SHIFT);
}

/*
 * Since some arches are moving towards PAGE_KERNEL module allocations instead
 * of PAGE_KERNEL_EXEC, keep module_enable_x() independent of
 * CONFIG_STRICT_MODULE_RWX because they are needed regardless of whether we
 * are strict.
 */
void module_enable_x(const struct module *mod)
{
	module_set_memory(mod, MOD_MEM_TYPE_TEXT, set_memory_x);
	module_set_memory(mod, MOD_MEM_TYPE_INIT_TEXT, set_memory_x);
}

void module_enable_ro(const struct module *mod, bool after_init)
{
	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		return;
#ifdef CONFIG_STRICT_MODULE_RWX
	if (!rodata_enabled)
		return;
#endif

	module_set_memory(mod, MOD_MEM_TYPE_TEXT, set_memory_ro);
	module_set_memory(mod, MOD_MEM_TYPE_INIT_TEXT, set_memory_ro);
	module_set_memory(mod, MOD_MEM_TYPE_RODATA, set_memory_ro);
	module_set_memory(mod, MOD_MEM_TYPE_INIT_RODATA, set_memory_ro);

	if (after_init)
		module_set_memory(mod, MOD_MEM_TYPE_RO_AFTER_INIT, set_memory_ro);
}

void module_enable_nx(const struct module *mod)
{
	enum mod_mem_type type;

	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		return;

	for_each_mod_mem_type(type) {
		if (type == MOD_MEM_TYPE_TEXT || type == MOD_MEM_TYPE_INIT_TEXT)
			continue;
		module_set_memory(mod, type, set_memory_nx);
	}
}

int module_enforce_rwx_sections(Elf_Ehdr *hdr, Elf_Shdr *sechdrs,
				char *secstrings, struct module *mod)
{
	const unsigned long shf_wx = SHF_WRITE | SHF_EXECINSTR;
	int i;

	if (!IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		return 0;

	for (i = 0; i < hdr->e_shnum; i++) {
		if ((sechdrs[i].sh_flags & shf_wx) == shf_wx) {
			pr_err("%s: section %s (index %d) has invalid WRITE|EXEC flags\n",
			       mod->name, secstrings + sechdrs[i].sh_name, i);
			return -ENOEXEC;
		}
	}

	return 0;
}
