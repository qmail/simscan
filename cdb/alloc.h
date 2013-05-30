#ifndef ALLOC_H
#define ALLOC_H

extern /*@null@*//*@out@*/char *alloc(unsigned int n);
extern void alloc_free(char *x);
extern int alloc_re();

#endif
