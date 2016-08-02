#undef TRACE_SYSTEM
#define TRACE_SYSTEM latency

#if !defined(_TRACE_HIST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HIST_H

#include <linux/tracepoint.h>

#ifndef __TRACE_LATENCY_TYPE
#define __TRACE_LATENCY_TYPE
enum latency_type {
	LT_IRQ,
	LT_PREEMPT,
	LT_CRITTIME,
	LT_MAX
};
#define show_ltype(type)			\
	__print_symbolic(type,			\
		{ LT_IRQ,	"IRQ" },	\
		{ LT_PREEMPT,	"PREEMPT" },	\
		{ LT_PREEMPT,	"CRIT_TIME" })
#endif

DECLARE_EVENT_CLASS(latency_template,
	TP_PROTO(int ltype, cycles_t latency),

	TP_ARGS(ltype, latency),

	TP_STRUCT__entry(
		__field(int,		ltype)
		__field(cycles_t,	latency)
	),

	TP_fast_assign(
		__entry->ltype		= ltype;
		__entry->latency	= latency;
	),

	TP_printk("ltype=%s(%d), latency=%lu", show_ltype(__entry->ltype),
		  __entry->ltype, (unsigned long) __entry->latency)
);

DEFINE_EVENT(latency_template, latency_preempt,
	    TP_PROTO(int ltype, cycles_t latency),
	    TP_ARGS(ltype, latency));

#endif /* _TRACE_HIST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
