#ifndef REVERSE_GENERATOR_
#define REVERSE_GENERATOR_

/**
 * Increment the current era. From this follows that if
 * the current era is grater than the last one, as soon as
 * the monitor module would be called, a new reverse window
 * would be created.
 *
 * @return Returns the current era value
 */
inline int increment_era ();


/**
 * This will free the last reverse window from the history.
 */
inline void free_last_revwin ();


/**
 * Initializes monitor's data structure.
 * It is mandatory to call it at the beginning of the execution
 */
inline void monitor_initialize();

#endif // REVERSE_GENERATOR_
