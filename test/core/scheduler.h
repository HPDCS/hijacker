#pragma once

extern unsigned int num_entities;

#define INSPECT_AFTER_EVENTS 100000

extern void ScheduleNewEvent(unsigned int receiver, double timestamp, unsigned int event_type, void *event_content, unsigned int event_size);
extern void SetState(void *state);
