// SPDX-License-Identifier: GPL-2.0
#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/irqnr.h>
#include <linux/sched/cputime.h>
#include <linux/tick.h>
// manish begin
#include <linux/manish.h>
// manish end

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

#ifdef arch_idle_time

u64 get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 idle;

	idle = kcs->cpustat[CPUTIME_IDLE];
	if (cpu_online(cpu) && !nr_iowait_cpu(cpu))
		idle += arch_idle_time(cpu);
	return idle;
}

static u64 get_iowait_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 iowait;

	iowait = kcs->cpustat[CPUTIME_IOWAIT];
	if (cpu_online(cpu) && nr_iowait_cpu(cpu))
		iowait += arch_idle_time(cpu);
	return iowait;
}

#else

u64 get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 idle, idle_usecs = -1ULL;

	if (cpu_online(cpu))
		idle_usecs = get_cpu_idle_time_us(cpu, NULL);

	if (idle_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.idle */
		idle = kcs->cpustat[CPUTIME_IDLE];
	else
		idle = idle_usecs * NSEC_PER_USEC;

	return idle;
}

static u64 get_iowait_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 iowait, iowait_usecs = -1ULL;

	if (cpu_online(cpu))
		iowait_usecs = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.iowait */
		iowait = kcs->cpustat[CPUTIME_IOWAIT];
	else
		iowait = iowait_usecs * NSEC_PER_USEC;

	return iowait;
}

#endif

static void show_irq_gap(struct seq_file *p, unsigned int gap)
{
	static const char zeros[] = " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

	while (gap > 0) {
		unsigned int inc;

		inc = min_t(unsigned int, gap, ARRAY_SIZE(zeros) / 2);
		seq_write(p, zeros, 2 * inc);
		gap -= inc;
	}
}

static void show_all_irqs(struct seq_file *p)
{
	unsigned int i, next = 0;

	for_each_active_irq(i) {
		show_irq_gap(p, i - next);
		seq_put_decimal_ull(p, " ", kstat_irqs_usr(i));
		next = i + 1;
	}
	show_irq_gap(p, nr_irqs - next);
}

static int show_stat(struct seq_file *p, void *v)
{
	int i, j;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
	struct timespec64 boottime;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = guest_nice = 0;
	getboottime64(&boottime);
	/* shift boot timestamp according to the timens offset */
	timens_sub_boottime(&boottime);

	for_each_possible_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;

		kcpustat_cpu_fetch(&kcpustat, i);

		user		+= cpustat[CPUTIME_USER];
		nice		+= cpustat[CPUTIME_NICE];
		system		+= cpustat[CPUTIME_SYSTEM];
		idle		+= get_idle_time(&kcpustat, i);
		iowait		+= get_iowait_time(&kcpustat, i);
		irq		+= cpustat[CPUTIME_IRQ];
		softirq		+= cpustat[CPUTIME_SOFTIRQ];
		steal		+= cpustat[CPUTIME_STEAL];
		guest		+= cpustat[CPUTIME_GUEST];
		guest_nice	+= cpustat[CPUTIME_GUEST_NICE];
		sum		+= kstat_cpu_irqs_sum(i);
		sum		+= arch_irq_stat_cpu(i);

		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			per_softirq_sums[j] += softirq_stat;
			sum_softirq += softirq_stat;
		}
	}
	sum += arch_irq_stat();

	seq_put_decimal_ull(p, "cpu  ", nsec_to_clock_t(user));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest_nice));
	seq_putc(p, '\n');

	for_each_online_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;

		kcpustat_cpu_fetch(&kcpustat, i);

		/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
		user		= cpustat[CPUTIME_USER];
		nice		= cpustat[CPUTIME_NICE];
		system		= cpustat[CPUTIME_SYSTEM];
		idle		= get_idle_time(&kcpustat, i);
		iowait		= get_iowait_time(&kcpustat, i);
		irq		= cpustat[CPUTIME_IRQ];
		softirq		= cpustat[CPUTIME_SOFTIRQ];
		steal		= cpustat[CPUTIME_STEAL];
		guest		= cpustat[CPUTIME_GUEST];
		guest_nice	= cpustat[CPUTIME_GUEST_NICE];
		seq_printf(p, "cpu%d", i);
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(user));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest_nice));
		seq_putc(p, '\n');
	}
	seq_put_decimal_ull(p, "intr ", (unsigned long long)sum);

	show_all_irqs(p);

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %llu\n"
		"processes %lu\n"
		"procs_running %u\n"
		"procs_blocked %u\n",
		nr_context_switches(),
		(unsigned long long)boottime.tv_sec,
		total_forks,
		nr_running(),
		nr_iowait());

	seq_put_decimal_ull(p, "softirq ", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_put_decimal_ull(p, " ", per_softirq_sums[i]);
	seq_putc(p, '\n');

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	unsigned int size = 1024 + 128 * num_online_cpus();

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;
	return single_open_size(file, show_stat, NULL, size);
}

static const struct proc_ops stat_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= stat_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

// manish begin

static int manish_show(struct seq_file *f, void *p)
{
	manish_print_sk_map(f);
	return 0;
}

static int manish_open(struct inode *inode, struct file *file)
{
	return single_open(file, manish_show, NULL);
}

static ssize_t manish_write(struct file *f, const char __user *ubuf, size_t n, loff_t *off)
{
	char kbuf[10] = { 0 };
	n = (n > 9) ? 9 : n;
	if (copy_from_user(kbuf, ubuf, n))
		return -EFAULT;
	n = strlen(kbuf);

	if (strncmp(kbuf, "0", 1) == 0)
		MANISH_DEBUG = 0;
	else if (strncmp(kbuf, "1", 1) == 0)
		MANISH_DEBUG = 1;
	else if (strncmp(kbuf, "clear", 5) == 0)
		manish_sk_remove_all();

	*off = n;
	return n;
}

static const struct proc_ops manish_proc_ops = {
	.proc_open = manish_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = manish_write,
};

// manish end

static int __init proc_stat_init(void)
{
	proc_create("stat", 0, NULL, &stat_proc_ops);
	// manish begin
	proc_create("manish", 0666, NULL, &manish_proc_ops);
	// manish end
	return 0;
}
fs_initcall(proc_stat_init);
