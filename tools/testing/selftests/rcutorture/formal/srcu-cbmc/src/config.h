/* SPDX-License-Identifier: GPL-2.0 */
/* "Cheater" definitions based on restricted Kconfig choices. */

#undef CONFIG_TINY_RCU
#undef __CHECKER__
#undef CONFIG_DEBUG_LOCK_ALLOC
#undef CONFIG_DEBUG_OBJECTS_RCU_HEAD
#undef CONFIG_HOTPLUG_CPU
#undef CONFIG_MODULES
#undef CONFIG_NO_HZ_FULL_SYSIDLE
#undef CONFIG_PREEMPT_RCU
#undef CONFIG_PROVE_RCU
#undef CONFIG_RCU_NOCB_CPU
#undef CONFIG_RCU_NOCB_CPU_ALL
#undef CONFIG_RCU_STALL_COMMON
#undef CONFIG_RCU_TRACE
#undef CONFIG_RCU_USER_QS
#undef CONFIG_TASKS_RCU
#define CONFIG_TREE_RCU

#define CONFIG_GENERIC_ATOMIC64

#if NR_CPUS > 1
#define CONFIG_SMP
#else
#undef CONFIG_SMP
#endif
