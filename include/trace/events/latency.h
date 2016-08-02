#undef TRACE_SYSTEM
#define TRACE_SYSTEM latency

#if !defined(_TRACE_HIST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HIST_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(latency_template,
	TP_PROTO(int ltype, int cpu, cycles_t latency),

	TP_ARGS(ltype, cpu, latency),

	TP_STRUCT__entry(
		__field(int,		ltype)
		__field(int,		cpu)
		__field(cycles_t,	latency)
	),

	TP_fast_assign(
		__entry->ltype		= ltype;
		__entry->cpu		= cpu;
		__entry->latency	= latency;
	),

	TP_printk("ltype=%d, cpu=%d, latency=%lu",
		__entry->ltype, __entry->cpu, (unsigned long) __entry->latency)
);

DEFINE_EVENT(latency_template, latency_preempt,
	    TP_PROTO(int ltype, int cpu, cycles_t latency),
	    TP_ARGS(ltype, cpu, latency));

#endif /* _TRACE_HIST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
