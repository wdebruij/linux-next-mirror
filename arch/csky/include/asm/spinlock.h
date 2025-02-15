/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_CSKY_SPINLOCK_H
#define __ASM_CSKY_SPINLOCK_H

#include <asm/qrwlock.h>
#include <asm/qspinlock.h>

/* See include/linux/spinlock.h */
#define smp_mb__after_spinlock()	smp_mb()

#endif /* __ASM_CSKY_SPINLOCK_H */
