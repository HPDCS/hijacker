#pragma once

#include <stdbool.h>

// Events
#define INIT		0
#define START_CALL	20
#define END_CALL	21
#define HANDOFF_LEAVE	30
#define HANDOFF_RECV	31

// Simulation Configuration
#define CHECK_FADING_TIME	10
#define COMPLETE_CALLS		5000

#ifndef TA
#define TA			0.5
#endif

#define TA_DURATION		120
#define CHANNELS_PER_CELL	1000
#define TA_CHANGE		300.0


// Constants for accurate simulation
#define CROSS_PATH_GAIN		0.00000000000005
#define PATH_GAIN		0.0000000001
#define MIN_POWER		3
#define MAX_POWER		3000
#define SIR_AIM			10

// Constants to determine the workload depending on time
#define HOUR			3600
#define DAY			(24 * HOUR)
#define WEEK			(7 * DAY)

#define EARLY_MORNING		8.5 * HOUR
#define MORNING			13 * HOUR
#define LUNCH			15 * HOUR
#define AFTERNOON		19 * HOUR
#define EVENING			21 * HOUR

#define EARLY_MORNING_FACTOR	4
#define MORNING_FACTOR		0.8
#define LUNCH_FACTOR		2.5
#define AFTERNOON_FACTOR	2
#define EVENING_FACTOR		2.2
#define NIGHT_FACTOR		4.5
#define WEEKEND_FACTOR		5



// Macros to manage channels bitmap
#define MSK 0x1
#define SET_CHANNEL_BIT(B,K) ( B |= (MSK << K) )
#define RESET_CHANNEL_BIT(B,K) ( B &= ~(MSK << K) )
#define CHECK_CHANNEL_BIT(B,K) ( B & (MSK << K) )

#define BITS (sizeof(int) * 8)

#define CHECK_CHANNEL(P,I) ( CHECK_CHANNEL_BIT(						\
	((unsigned int*)(((entity_state*)P)->channel_state))[(int)((int)I / BITS)],	\
	((int)I % BITS)) )
#define SET_CHANNEL(P,I) ( SET_CHANNEL_BIT(						\
	((unsigned int*)(((entity_state*)P)->channel_state))[(int)((int)I / BITS)],	\
	((int)I % BITS)) )
#define RESET_CHANNEL(P,I) ( RESET_CHANNEL_BIT(						\
	((unsigned int*)(((entity_state*)P)->channel_state))[(int)((int)I / BITS)],	\
	((int)I % BITS)) )


// Event Structure
typedef struct _event_content_type {
	unsigned int 	cell;
	unsigned int 	from;
	double 		sent_at;
	int 		channel;
	double		call_term_time;
} event_content_type;


// SIR data (for accurate simulation)
typedef struct _sir_data_per_cell{
    double fading;
    double power;
} sir_data_per_cell;


// Channel structure list
typedef struct _channel{
	int channel_id;
	sir_data_per_cell *sir_data;
	struct _channel *next;
	struct _channel *prev;
} channel;

// Simulation state of each entity
typedef struct _entity_state{
	long idum;
	unsigned int channel_counter;
	unsigned int arriving_calls;
	unsigned int complete_calls;
	unsigned int blocked_on_setup;
	unsigned int blocked_on_handoff;
	unsigned int leaving_handoffs;
	unsigned int arriving_handoffs;
	unsigned int cont_no_sir_aim;
	double lvt;
	double ta;
	int channels_per_cell;
	int total_calls;
	unsigned int *channel_state;
	struct _channel *channels;
} entity_state;




extern void ProcessEvent(unsigned int me, double now, int event_type, event_content_type *event_content, unsigned int size, entity_state *state);
extern bool OnGVT(unsigned int me, entity_state *snapshot);
