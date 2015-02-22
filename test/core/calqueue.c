#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>

#include "calqueue.h"


		
		
		
static calqueue_node *calqueue_deq(calqueue *q);





/* This initializes a bucket array within the array a[].
   Bucket width is set equal to bwidth. Bucket[0] is made
   equal to a[qbase]; and the number of buckets is nbuck.
   Startprio is the priority at which dequeueing begins.
   All external variables except resize_enabled are
   initialized
*/
static void localinit(calqueue *q, int qbase, int nbucks, double bwidth, double startprio) {

	int i;
	long int n;

	// Set position and size of new queue
	q->firstsub = qbase;
	q->calendar = q->calq + qbase;
	q->cwidth = bwidth;
	q->nbuckets = nbucks;

	// Init as empty
	q->qsize = 0;
	for(i = 0; i < q->nbuckets; i++) {
		q->calendar[i] = NULL;
	}
	
	// Setup initial position in queue
	q->lastprio = startprio;
	n = (long)((double)startprio / q->cwidth);	// Virtual bucket
	q->lastbucket = n % q->nbuckets;
	q->buckettop = (double)(n + 1) * q->cwidth + 0.5 * q->cwidth;

	// Setup queue-size-change thresholds
	q->bot_threshold = (int)((double)q->nbuckets / 2) - 2;
	q->top_threshold = 2 * q->nbuckets;
}


// This function returns the width that the buckets should have
// based on a random sample of the queue so that there will be about 3
// items in each bucket.
static double new_width(calqueue *q) {

	int nsamples, templastbucket, i, j;
	double templastprio;
	double tempbuckettop, average, newaverage;
	calqueue_node *temp[25];

	// Init the temp node structure
	for(i = 0; i < 25; i++) {
		temp[i] = NULL;
	}

	// How many queue elements to sample?
	if(q->qsize < 2)
		return 1.0;

	if(q->qsize <= 5)
		nsamples = q->qsize;
	else
		nsamples = 5 + (int)((double)q->	qsize / 10);

	if(nsamples > 25)
		nsamples = 25;

	// Store the current situation
	templastbucket = q->lastbucket;
	templastprio = q->lastprio;
	tempbuckettop = q->buckettop;

	q->resize_enabled = false;
	average = 0.;

	for(i = 0; i < nsamples; i++) {
		// Dequeue nodes to get a test sample and sum up the differences in time
		temp[i] = calqueue_deq(q);
		if(i > 0)
			average += temp[i]->priority - temp[i-1]->priority;
	}

	// Get the average
	average = average / (double)(nsamples - 1);

	newaverage = 0.;
	j = 0;

	// Re-insert temp node 0
	calqueue_put(q, temp[0]->priority, temp[0]->payload);
	
	// Recalculate ignoring large separations
	for(i = 1; i < nsamples; i++) {
		if((temp[i]->priority - temp[i-1]->priority) < (average * 2.0)) {
			newaverage += (temp[i]->priority - temp[i-1]->priority);
			j++;
		}
		calqueue_put(q, temp[i]->priority, temp[i]->payload);
	}
	
	// Free the temp structure (the events have been re-injected in the queue)
	for(i = 0; i < 25; i++) {
		if(temp[i] != NULL) {
			free(temp[i]);
		}
	}

	// Compute new width
	newaverage = (newaverage / (double)j) * 3.0;      /* this is the new width */

	// Restore the original condition
	q->lastbucket = templastbucket;           /* restore the original conditions */
	q->lastprio = templastprio;
	q->buckettop = tempbuckettop;
	q->resize_enabled = true;

	return newaverage;
}


// This copies the queue onto a calendar with nnewsize buckets. The new bucket
// array is on the opposite end of the array a[QSPACE] from the original        EH?!?!?!?!?!
static void resize(calqueue *q, int newsize) {
	double bwidth;
	int i;
	int oldnbuckets;
	calqueue_node **oldcalendar, *temp, *temp2;

	if(!q->resize_enabled)
		return;

	// Find new bucket width
	bwidth = new_width(q);

	// Save location and size of old calendar for use when copying calendar
	oldcalendar = q->calendar;
	oldnbuckets = q->nbuckets;

	// Init the new calendar
	if(q->firstsub == 0) {
		localinit(q, CALQSPACE - newsize, newsize, bwidth, q->lastprio);
	} else {
		localinit(q, 0, newsize, bwidth, q->lastprio);
	}

	// Copy elements to the new calendar
	for(i = oldnbuckets - 1; i >= 0; --i) {
		temp = oldcalendar[i];
		while(temp != NULL) {
			calqueue_put(q, temp->priority, temp->payload);
			temp2 = temp->next;
			free(temp);
			temp = temp2;
		}
	}
}



static calqueue_node *calqueue_deq(calqueue *q) {

	register int i;
	int temp2;
	calqueue_node *e;
	double lowest;

	// Is there an event to be processed?
	if(q->qsize == 0) {
		return NULL;
	}

	for(i = q->lastbucket; ;) {
		// Check bucket i
		if(q->calendar[i] != NULL && q->calendar[i]->priority < q->buckettop) {

		    calendar_process:

			// Found an item to be processed
			e = q->calendar[i];

			// Update position on calendar and queue's size
			q->lastbucket = i;
			q->lastprio = e->priority;
			q->qsize--;

			// Remove the event from the calendar queue
			q->calendar[i] = q->calendar[i]->next;

			// Halve the calendar size if needed
			if(q->qsize < q->bot_threshold)
				resize(q, (int)((double)q->nbuckets / 2));

			// Processing completed
			return e;

		} else {
			// Prepare to check the next bucket, or go to a direct search
			i++;
			if(i == q->nbuckets)
				i = 0;

			q->buckettop += q->cwidth;

			if(i == q->lastbucket)
				break; // Go to direct search
		}
	}

	// Directly search for minimum priority event
	temp2 = -1;
	lowest = (double)LLONG_MAX;
	for(i = 0; i < q->nbuckets; i++) {
		if((q->calendar[i] != NULL) && ((temp2 == -1) || (q->calendar[i]->priority < lowest))) {
			temp2 = i;
			lowest = q->calendar[i]->priority;
		}
	}

	// Process the event found and and handle the queue
	i = temp2;
	goto calendar_process;

	// To make the compiler happy!
	return NULL;

}





// This function initializes the messaging queue.
void calqueue_init(calqueue *q) {

	localinit(q, 0, 2, 1.0, 0.0);
	q->resize_enabled = true;
}





void calqueue_put(calqueue *q, double priority, void *payload) {

	int i;
	calqueue_node *new_node, *traverse;

	// Fill the node entry
	new_node = malloc(sizeof(calqueue_node));
	new_node->priority = priority;
	new_node->payload = payload;
	new_node->next = NULL;


	// Calculate the number of the bucket in which to place the new entry
	i = (int)(priority / (double)q->cwidth); // Virtual bucket
	i = i % q->nbuckets; // Actual bucket

	// Grab the head of events list in bucket i
	traverse = q->calendar[i];

	// Put at the head of the list, if appropriate
	if(traverse == NULL || traverse->priority > priority) {
		new_node->next = traverse;
		q->calendar[i] = new_node;
	} else {
		// Find the correct place in list
		while(traverse->next != NULL && traverse->next->priority <= priority)
			traverse = traverse->next;

		// Place the new event
		new_node->next = traverse->next;
		traverse->next = new_node;
	}
	
	// Update queue size
	q->qsize++;

	// Double the calendar size if needed
	if(q->qsize > q->top_threshold && q->nbuckets < MAXNBUCKETS) {
		resize(q, 2 * q->nbuckets);
	}
}



void *calqueue_get(calqueue *q) {
	calqueue_node *node;
	void *payload;
		
	node = calqueue_deq(q);
	if(node == NULL) {
		return NULL;
	}
	
	payload = node->payload;
	free(node);
	return payload;
}


bool calqueue_empty(calqueue *q) {
	return (q->qsize == 0);
}
