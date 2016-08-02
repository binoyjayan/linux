#undef TRACE_SYSTEM
#define TRACE_SYSTEM latency

#if !defined(_TRACE_HIST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HIST_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(latency_template,
	TP_PROTO(cycles_t latency),

	TP_ARGS(latency),

	TP_STRUCT__entry(
		__field(cycles_t,	latency)
	),

	TP_fast_assign(
		__entry->latency	= latency;
	),

	TP_printk("latency=%lu", __entry->latency)
);

DEFINE_EVENT(latency_template, latency_irqs,
	    TP_PROTO(cycles_t latency),
	    TP_ARGS(latency));

DEFINE_EVENT(latency_template, latency_preempt,
	    TP_PROTO(cycles_t latency),
	    TP_ARGS(latency));

DEFINE_EVENT(latency_template, latency_critical_timings,
	    TP_PROTO(cycles_t latency),
	    TP_ARGS(latency));

#endif /* _TRACE_HIST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
