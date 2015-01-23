/*
 * utils.h
 *
 *  Created on: 17/apr/2014
 *      Author: davide
 */

#ifndef _UTILS_H_
#define _UTILS_H_

/**
 * Perform a hexdump of data.
 * Stores into a preallocated buffer, pointed to by the 'dump' argument,
 * the hexadecimal dump of the 'len' bytes found starting from 'addr' pointer.
 *
 * @param addr Pointer to the data buffer to dump
 *
 * @param len Number of byte to read
 */
void hexdump (void *addr, int len);

#endif /* _UTILS_H_ */
