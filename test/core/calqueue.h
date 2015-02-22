#pragma once
#ifndef __CALQUEUE_H
#define __CALQUEUE_H

#include <stdbool.h>

#define CALQSPACE 65536		// Calendar array size needed for maximum resize
#define MAXNBUCKETS 32768	// Maximum number of buckets in calendar queue

typedef struct __calqueue_node {
	double			priority; // Priority associated to the event
	void 			*payload; // A pointer to the actual content of the node
	struct __calqueue_node 	*next;		// Pointers to other nodes
} calqueue_node;

typedef struct __calqueue_node *calendar_queue;

typedef struct __calqueue {
	// Declare data structures needed for the schedulers
	calqueue_node *calq[CALQSPACE];	// Array of linked lists of items
	calqueue_node **calendar;		// Pointer to use as a sub-array to calq

	// Global variables for the calendar queueing routines
	int 	firstsub,
		nbuckets,
		qsize,
		lastbucket;
	bool	resize_enabled;
	double	top_threshold,
		bot_threshold,
		lastprio;

	double	buckettop,
		cwidth;
} calqueue;



extern void calqueue_init(calqueue *);
extern void *calqueue_get(calqueue *);
extern void calqueue_put(calqueue *, double, void *);
extern bool calqueue_empty(calqueue *);

#endif /* __CALQUEUE_H */
