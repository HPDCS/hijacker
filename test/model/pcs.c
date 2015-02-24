#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "scheduler.h"
#include "pcs.h"
#include "rng.h"


// This is used to change the workload depending on the simulation time reached
static double recompute_ta(double ref_ta, double time_now) {

	int now = (int)time_now;
	now %= WEEK;

	if (now > 5 * DAY)
		return ref_ta * WEEKEND_FACTOR;

	now %= DAY;

	if (now < EARLY_MORNING)
		return ref_ta * EARLY_MORNING_FACTOR;
	if (now < MORNING)
		return ref_ta * MORNING_FACTOR;
	if (now < LUNCH)
		return ref_ta * LUNCH_FACTOR;
	if (now < AFTERNOON)
		return ref_ta * AFTERNOON_FACTOR;
	if (now < EVENING)
		return ref_ta * EVENING_FACTOR;

	return ref_ta * NIGHT_FACTOR;
}

static double generate_cross_path_gain(entity_state *state) {
	double value;
	double variation;

	variation = 10 * Random(&state->idum);
	variation = pow((double)10.0 , (variation / 10));
	value = CROSS_PATH_GAIN * variation;
	return (value);
}

static double generate_path_gain(entity_state *state) {
	double value;
	double variation;

	variation = 10 * Random(&state->idum);
	variation = pow ((double)10.0 , (variation / 10));
	value = PATH_GAIN * variation;
	return (value);
}

static void deallocation(unsigned int me, entity_state *state, int ch, double lvt) {
	channel *c;

	c = state->channels;
	while(c != NULL){
		if(c->channel_id == ch)
			break;
		c = c->prev;
	}
	if(c != NULL){
		if(c == state->channels){
			state->channels = c->prev;
			if(state->channels)
				state->channels->next = NULL;
		}
		else{
			if(c->next != NULL)
				c->next->prev = c->prev;
			if(c->prev != NULL)
				c->prev->next = c->next;
		}
		RESET_CHANNEL(state, ch);
		free(c->sir_data);

		free(c);
	} else {
		printf("(%d) Unable to deallocate on %p, channel is %d at time %f\n", me, c, ch, lvt);
		abort();
	}
	return;
}

static int allocation(entity_state *state) {

	int i;
  	int index;
	double summ;

	channel *c, *ch;

	index = -1;
	for(i = 0; i < CHANNELS_PER_CELL; i++){
		if(!CHECK_CHANNEL(state,i)){
			index = i;
			break;
		}
	}

	if(index != -1){

		SET_CHANNEL(state,index);

		c = (channel*)malloc(sizeof(channel));
		if(c == NULL){
			printf("malloc error: unable to allocate channel!\n");
			exit(-1);
		}

		c->next = NULL;
		c->prev = state->channels;
		c->channel_id = index;
		c->sir_data = (sir_data_per_cell*)malloc(sizeof(sir_data_per_cell));
		if(c->sir_data == NULL){
			printf("malloc error: unable to allocate SIR data!\n");
			exit(-1);
		}

		if(state->channels != NULL)
			state->channels->next = c;
		state->channels = c;

		// Check fading
		summ = 0.0;
		ch = state->channels->prev;
		while(ch != NULL){
			ch->sir_data->fading = Expent(&state->idum, 1.0);
			summ += generate_cross_path_gain(state) *  ch->sir_data->power * ch->sir_data->fading ;
			ch = ch->prev;
		}

		if (summ == 0.0) {
			// The newly allocated channel receives the minimal power
			c->sir_data->power = MIN_POWER;
		} else {
		  	c->sir_data->fading = Expent(&state->idum, 1.0);
			c->sir_data->power = ((SIR_AIM * summ) / (generate_path_gain(state) * c->sir_data->fading));
			if (c->sir_data->power < MIN_POWER) c->sir_data->power = MIN_POWER;
			if (c->sir_data->power > MAX_POWER) c->sir_data->power = MAX_POWER;
		}

	} else {
		printf("Unable to allocate channel, but the counter says I have %d available channels\n", state->channel_counter);
		abort();
		fflush(stdout);
	}

        return index;
}



unsigned int FindReceiver(unsigned int me, entity_state *state) {

	// receiver is not unsigned, because we exploit -1 as a border case in the bidring topology.
	unsigned int receiver;

 	// These must be unsigned. They are not checked for negative (wrong) values,
 	// but they would overflow, and are caught by a different check.
 	unsigned int edge;
 	unsigned int x, y, nx, ny;

	#define NW	0
	#define W	1
	#define SW	2
	#define SE	3
	#define E	4
	#define NE	5

	// Convert linear coords to hexagonal coords
	edge = sqrt(num_entities);
	x = me % edge;
	y = me / edge;

	// Sanity check!
	if(edge * edge != num_entities) {
		fprintf(stderr, "Hexagonal map wrongly specified!\n");
		abort();
	}

	// Very simple case!
	if(num_entities == 1) {
		return me;
	}

	// Select a random neighbour once, then move counter clockwise
	receiver = 6 * Random(&state->idum);
	bool invalid = false;

	// Find a random neighbour
	do {
		if(invalid) {
			receiver = (receiver + 1) % 6;
		}

		switch(receiver) {
			case NW:
				nx = (y % 2 == 0 ? x - 1 : x);
				ny = y - 1;
				break;
			case NE:
				nx = (y % 2 == 0 ? x : x + 1);
				ny = y - 1;
				break;
			case SW:
				nx = (y % 2 == 0 ? x - 1 : x);
				ny = y + 1;
				break;
			case SE:
				nx = (y % 2 == 0 ? x : x + 1);
				ny = y + 1;
				break;
			case E:
				nx = x + 1;
				ny = y;
				break;
			case W:
				nx = x - 1;
				ny = y;
				break;
			default:
				fprintf(stderr, "Met an impossible condition at %s:%d. Aborting...\n", __FILE__, __LINE__);
				abort();
		}

		invalid = true;

	// We don't check is nx < 0 || ny < 0, as they are unsigned and therefore overflow
	} while(nx >= edge || ny >= edge);

	// Convert back to linear coordinates
	receiver = (ny * edge + nx);

	#undef NE
	#undef NW
	#undef W
	#undef SW
	#undef SE
	#undef E

	return receiver;

}


void ProcessEvent(unsigned int me,
		  double now,
		  int event_type,
		  event_content_type *event_content,
		  unsigned int size, entity_state *state) {

	channel *c;
	unsigned int i;

	(void)size;

	event_content_type new_event_content;

	new_event_content.cell = -1;
	new_event_content.channel = -1;
	new_event_content.call_term_time = -1;

	double handoff_time;
	double timestamp = 0;

	if(state != NULL) {
		state->lvt = now;
	}

	switch(event_type) {

		case INIT:

			// Initialize the LP's state
			state = (entity_state *)malloc(sizeof(entity_state));
			if (state == NULL){
				printf("Out of memory!\n");
				exit(EXIT_FAILURE);
			}

			SetState(state);

			if(me == 0) {
				printf("Running with TA %f\n", TA);
			}

			Srand(&state->idum);

			bzero(state, sizeof(entity_state));
			state->channel_counter = CHANNELS_PER_CELL;

			// Setup channel state
			state->channel_state = malloc(sizeof(unsigned int) * 2 * (CHANNELS_PER_CELL / BITS + 1));
			for (i = 0; i < state->channel_counter / (sizeof(int) * 8) + 1; i++)
				state->channel_state[i] = 0;

			// Start the simulation
			timestamp = (double) (20 * Random(&state->idum));
			ScheduleNewEvent(me, timestamp, START_CALL, NULL, 0);

			break;

		case START_CALL:

			state->arriving_calls++;

			if (state->channel_counter == 0) {
				state->blocked_on_setup++;
			} else {

				state->channel_counter--;

				new_event_content.channel = allocation(state);
				new_event_content.from = me;
				new_event_content.sent_at = now;

				// Determine call duration
				new_event_content.call_term_time = now + (double)(Expent(&state->idum, TA_DURATION));

				// Determine whether the call will be handed-off or not
				handoff_time = now + (double)(Expent(&state->idum, TA_CHANGE));

				// Collect a state to the freshly allocated channel
				c = state->channels;
				while(c != NULL){
				if(c->channel_id == new_event_content.channel)
					break;
					c = c->prev;
				}

				if(new_event_content.call_term_time <= handoff_time) {
					ScheduleNewEvent(me, new_event_content.call_term_time, END_CALL, &new_event_content, sizeof(new_event_content));
				} else {
					new_event_content.cell = FindReceiver(me, state);
					ScheduleNewEvent(me, handoff_time, HANDOFF_LEAVE, &new_event_content, sizeof(new_event_content));
				}
			}


			state->ta = recompute_ta(TA, now);

			// Determine the time at which the call will end
			timestamp= now + (double)(Expent(&state->idum, state->ta));

			ScheduleNewEvent(me, timestamp, START_CALL, NULL, 0);

			break;

		case END_CALL:

			state->channel_counter++;
			state->complete_calls++;
			deallocation(me, state, event_content->channel, now);

			break;

		case HANDOFF_LEAVE:

			state->channel_counter++;
			state->leaving_handoffs++;
			deallocation(me, state, event_content->channel, now);

			new_event_content.call_term_time =  event_content->call_term_time;
			ScheduleNewEvent(event_content->cell, now, HANDOFF_RECV, &new_event_content, sizeof(new_event_content));
			break;

        	case HANDOFF_RECV:
			state->arriving_handoffs++;
			state->arriving_calls++;

			if (state->channel_counter == 0)
				state->blocked_on_handoff++;
			else {
				state->channel_counter--;

				new_event_content.channel = allocation(state);
				new_event_content.call_term_time = event_content->call_term_time;

				handoff_time = now + (double)Expent(&state->idum, TA_CHANGE);

				if(new_event_content.call_term_time <=  handoff_time ) {
					ScheduleNewEvent(me , new_event_content.call_term_time, END_CALL, &new_event_content, sizeof(new_event_content));
				} else {
					new_event_content.cell = FindReceiver(me, state);
					ScheduleNewEvent(me , new_event_content.call_term_time, HANDOFF_LEAVE, &new_event_content, sizeof(new_event_content));
				}
			}
			break;

		default:
			fprintf(stdout, "PCS: Unknown event type! (me = %d - event type = %d)\n", me, event_type);
			abort();

	}
}


// Function to inspect the evolution of the simulation state
bool OnGVT(unsigned int me, entity_state *state) {
	printf("Cell %d at time %f has %d free channels, has received %d calls, %d have been completed, %d have been handed off\n",
		me,
		state->lvt,
		state->channel_counter,
		state->arriving_calls + state->arriving_handoffs,
		state->complete_calls,
		state->leaving_handoffs);

	// We will understand this later in the course
	return true;
}
