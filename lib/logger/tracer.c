
void dump(void);

void trace(unsigned long start, unsigned long size);


#ifdef TRACEFILE

#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <assert.h>
#include <stdarg.h>


#define xstr(s) str(s)
#define str(s) #s


#define eprintf(format, ...) do {\
	fprintf(stdout, format, ##__VA_ARGS__);\
	fflush(stdout);\
} while(0)

#define eprintf

#define USE_CACHE 1

/// Number of entries contained in the application buffer
#define BUFFER_LEN   (1 << 24)

/// Number of entries contained in the software cache
#define CACHE_LEN    (1 << 10)


#define withlock(lock, body) do {\
		if (atomic_flag_test_and_set((lock)) == false) {\
			(body)\
			atomic_flag_clear((lock));\
		}\
	} while(0);\


// NOTE: The `bbid` field includes the selection bit.
// For this reason, two entries with the same bbid but different
// selection bit must be considered two different entries.
typedef struct {
	unsigned long address;
	unsigned long count;
	unsigned long bbid;
} entry_t;


/// Pointer to the application buffer
static entry_t buffer[BUFFER_LEN];

#ifdef USE_CACHE
/// Pointer to the software cache
static entry_t cache[CACHE_LEN];
#endif

/// Next available index in the application buffer.
/// Updates at indexes strictly lower than this are allowed.
static _Atomic(unsigned long) nextpos = ATOMIC_VAR_INIT(0);

/// Maximum available index in the application buffer.
/// Insertions at indexes strictly lower than this are allowed.
static _Atomic(unsigned long) horizon = ATOMIC_VAR_INIT(BUFFER_LEN);

/// True if someone else is on that application buffer position
static atomic_flag buffering[BUFFER_LEN];

/// True if someone else is on that software cache line
static atomic_flag caching[CACHE_LEN];

/// Pointer to the file stream associated with the file dump
static FILE *fdump;

/// True if this module has been invoked at least once
static atomic_flag init = ATOMIC_FLAG_INIT;

/// True if the file dump has already been truncated
static atomic_flag append = ATOMIC_FLAG_INIT;

/// True if someone else is flushing the application buffer
static atomic_flag flushing = ATOMIC_FLAG_INIT;


bool entry_equal(entry_t *a, entry_t *b) {
	return (a->address == b->address && a->bbid == b->bbid);
}


unsigned long cache_hash(entry_t entry) {
	unsigned long a, msbs;

	// We know that on a 64 bit machine, virtual addresses are
	// never more than 48 bits wide
	a = entry.address;

	// Drop two LSBs
	a >>= 2;

	// Get rid of the MSBs and keep 46 bits
	a &= 0x3fffffffffff;

	// Get the 14 MSBs and fold them in to get a 32 bit integer
	// (the MSBs are mostly 0s, so we don't lose much entropy)
	msbs = (a >> 32) << 18;
	a ^= msbs;

	a = a + (entry.bbid << 6);

	// Pass this through a decent 'half avalanche' hash function,
	// meaning that each bit of the input gets a chance to affect
	// bits at the same position and higher:
	a = (a + 0x479ab41d) + (a << 8);
	a = (a ^ 0xe4aa10ce) ^ (a >> 5);
	a = (a + 0x9942f0a6) - (a << 14);
	a = (a ^ 0x5aedd67d) ^ (a >> 3);
	a = (a + 0x17bea992) + (a << 7);

	// Get N = CACHE_LEN MSBs to produce a key for the cache
	a = a & 0xffffffff;
	a = ((a * CACHE_LEN) >> 32);

	assert(a < CACHE_LEN);

	return a;
}


bool buffer_read(unsigned long pos, entry_t *entry) {
	bool read;

	if (entry == NULL || pos >= BUFFER_LEN) {
		return false;
	}

	read = false;

	// A read can never fail, but it can return stale entries.
	// (e.g., entries which have just been flushed).
	while (atomic_flag_test_and_set(&buffering[pos]) == true);

		*entry = buffer[pos];
		read = true;

	atomic_flag_clear(&buffering[pos]);

	return read;
}


bool buffer_store(entry_t entry) {
	bool cached, stored;
	unsigned long cpos, bpos, __bpos, __nextpos, __horizon;

	do {
		cached = false;
		stored = false;

		#ifdef USE_CACHE
		cpos = cache_hash(entry);
		assert(cpos < CACHE_LEN);
		#endif

		__nextpos = __bpos = atomic_load(&nextpos);
		__horizon = atomic_load(&horizon);

		// If the fetched `nextpos` value is equal to full capacity,
		// we need to wait until it is reset.
		if (__nextpos >= BUFFER_LEN) {
			continue;
		}

		// If the fetched `horizon` value is zero, we need to wait
		// until it becomes greater.
		if (__horizon == 0) {
			continue;
		}

		// ---------------------------------------
		// STEP 1: Try to read from cache
		// ---------------------------------------
		// A cache read fails when:
		// - The cache line holds another entry
		// - The cache line holds the same entry at an invalid position

		#ifdef USE_CACHE
		while (atomic_flag_test_and_set(&caching[cpos]) == true);

		if (entry_equal(&cache[cpos], &entry) && bpos < __nextpos) {
			cached = true;
		}

		// atomic_flag_clear(&caching[cpos]);

		// -------------------------------------
		// STEP 2a: Update application buffer
		// -------------------------------------
		// A buffer update fails when:
		// - The buffer line holds another entry

		if (cached == true) {
			bpos = cache[cpos].count;

			assert(bpos < BUFFER_LEN);

			if (atomic_flag_test_and_set(&buffering[bpos]) == true) {
				goto cache_release;
			}

			if (entry_equal(&buffer[bpos], &entry)) {
				buffer[bpos].count += entry.count;

				stored = true;
			}

			atomic_flag_clear(&buffering[bpos]);
		}
		#endif

		// -------------------------------------
		// STEP 2b: Append to application buffer
		// -------------------------------------
		// A buffer append fails when:
		// - The buffer line contains an entry which must be flushed
		// - The buffer line has been written by a concurrent thread

		if (stored == false) {
			bpos = __nextpos;
			__nextpos = bpos + 1;

			assert(bpos < BUFFER_LEN);

			if (atomic_flag_test_and_set(&buffering[bpos]) == true) {
				goto cache_release;
			}

			if (bpos < __horizon &&
			    atomic_compare_exchange_weak(&nextpos, &__bpos, __nextpos)) {
				buffer[bpos] = entry;

				#ifdef USE_CACHE
				cache[cpos] = entry;
				cache[cpos].count = bpos;
				#endif

				stored = true;
			}

			atomic_flag_clear(&buffering[bpos]);
		}

		// if (cached == false && stored == true) {
		// 	#ifdef USE_CACHE
		// 		// if (atomic_flag_test_and_set(&caching[cpos]) == true) {
		// 		// 	goto cache_release;
		// 		// }

		// 			cache[cpos] = entry;
		// 			cache[cpos].count = bpos;

		// 		// atomic_flag_clear(&caching[cpos]);
		// 	#endif
		// }

		cache_release:
			atomic_flag_clear(&caching[cpos]);

		// ------------------------------------
		// STEP 3: Flush application buffer
		// ------------------------------------

		// If the application buffer reached full capacity, flush it
		if (stored == true && __nextpos >= BUFFER_LEN) {
			dump();
			// atomic_store(&nextpos, 0);
		}

	} while (stored == false);

}

#endif


/**
 * Flushes the application buffer to disk and resets it so that it can be used
 * from scratch in future invocations of `trace`.
 */
void dump(void) {
	#ifdef TRACEFILE

	unsigned long long pos, __nextpos, size;

	entry_t entry;

	while (atomic_flag_test_and_set(&flushing) == true);

	// The first time contents of the file dump are truncated,
	// then contents are appended
	if (atomic_flag_test_and_set(&append) == false) {
		fdump = fopen(xstr(TRACEFILE), "w");
	}
	// else {
	// 	fdump = fopen(xstr(TRACEFILE), "a");
	// }

	// Load the current application buffer size into a temporary.
	// By the end of this loop, size will contain the latest
	// position written in the buffer and no one will be able to
	// further append new entries since `nextpos` is set to the
	// buffer's maximum capacity.

	do {
		size = __nextpos = atomic_load(&nextpos);
	} while (
		atomic_compare_exchange_weak(&nextpos, &__nextpos, BUFFER_LEN) == false
	);

	// From now on:
	// - NO new store operation of any type can start
	// - ONLY old store operation of 'update' type can complete

	// The order of the next two operations is important.
	// By re-setting `horizon` prior to `nextpos`, we prevent any
	// append occurring in between the two resets from overwriting
	// the first half of the buffer.

	// Reset the application buffer size.
	atomic_store(&horizon, 0);

	// At this point:
	// - old store operation of `update` type can STILL complete

	// Reset the application buffer index.
	atomic_store(&nextpos, 0);

	// At this point:
	// - NO old store operation of `update` type can complete

	// We are now ready to flush the application buffer to disk.
	// Every time an entry is read and flushed to disk in safety,
	// the application buffer horizon is increment by one to allow
	// for concurrent appends in the first half.
	for (pos = 0; pos < size; pos += 1) {
		buffer_read(pos, &entry);

		fprintf(fdump, "%p %u %u %u\n",
			entry.address, entry.count, entry.bbid >> 1, entry.bbid & 1);

		atomic_fetch_add(&horizon, 1);
	}

	// Close the file dump stream.
	// fclose(fdump);
	fflush(fdump);

	atomic_flag_clear(&flushing);
	#endif
}


/**
 * Stores the latest tracing information from the TLS buffer into a bigger
 * application buffer sized BUFFER_SIZE entries.
 * @param start Address of the TLS in which tracing information can be found
 * @param size  Total number of meaningful entries for the current instrumented
 *              function in the application
 */
void trace(unsigned long start, unsigned long size) {
	#ifdef TRACEFILE

	entry_t *tls;
	entry_t entry;

	unsigned long long i, pos;

	if (atomic_flag_test_and_set(&init) == false) {
		for (i = 0; i < BUFFER_LEN; i += 1) {
			atomic_flag_clear(&buffering[i]);
		}

		for (i = 0; i < CACHE_LEN; i += 1) {
			atomic_flag_clear(&caching[i]);
		}
	}

	// By definition each thread has its own TLS buffer, so we
	// don't have to synchronize accesses to this structure.
	tls = (entry_t *) start;

	for (i = 0; i < size; i += 1) {
		entry = tls[i];

		// Only process entries which have been actually populated
		// since the previous flush...
		if (entry.count == 0) {
			continue;
		}

		// Store the entry into the application buffer.
		buffer_store(entry);

		// Reset the access counter for the current TLS entry.
		tls[i].count = 0;
	}

	#endif
}
