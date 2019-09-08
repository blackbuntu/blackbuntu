/** list.h 
 * C version of linked lists
 * (ab)uing macros ...
 * (c) Kurt Garloff <kurt@garloff.de>, 1996 -- 2013
 * License: GNU GPL v2 or v3
 */

#ifndef _LIST_H
#define _LIST_H

#include <stdlib.h>

#define LISTDECL(type) 			\
struct _list_##type {			\
	struct _list_##type *next;	\
	type data;			\
}


#define LISTTYPE(type) struct _list_##type
#define LISTNEXT(x) x->next
#define LISTDATA(x) x->data

#define LISTINSAFTER(l, x, type) do {			\
	struct _list_##type *newel = (struct _list_##type *)malloc(sizeof(struct _list_##type));	\
	newel->data = x;				\
	if (l) {					\
		newel->next = l->next;			\
		l->next = newel;			\
	} else {					\
		l = newel;				\
		newel->next = 0;			\
	} 						\
	} while(0)

#define LISTINSBEFORE(lh, x, type) do {			\
	struct _list_##type *newel = (struct _list_##type *)malloc(sizeof(struct _list_##type));	\
	newel->data = x;				\
	newel->next = lh;				\
	lh = newel;					\
	} while (0)

#define LISTAPPEND(lh, x, type) do {		\
	struct _list_##type *newel = (struct _list_##type *)malloc(sizeof(struct _list_##type));	\
	newel->data = x; newel->next = 0;	\
	if (!lh)				\
		lh = newel;			\
	else {					\
		struct _list_##type *el = lh;	\
		while(el->next)			\
			el = el->next;		\
		el->next = newel;		\
	}					\
	} while (0)

#define LISTDELNEXT(l, type)	do {		\
	struct _list_##type *_nxt = l->next;	\
	if (l->next) {				\
		l->next = l->next->next;	\
		free(_nxt);			\
	} else {				\
		free(l);			\
		l = 0;				\
	} } while(0)

#define LISTDEL(l,prv,lhd,type) do { 		\
	struct _list_##type *_nxt = l->next;	\
	if (prv) prv->next = _nxt; else (lhd)->next = _nxt; \
	free(l);				\
	if (prv) l = prv; else l = lhd;		\
	} while (0)

#define LISTDEL1(lh,type) do { 			\
	struct _list_##type *_nxt = lh->next;	\
	free(lh);				\
	lh = _nxt;				\
	} while (0)

#define LISTTREEDEL(lh, type) do {		\
	while (lh) 				\
		LISTDEL1(lh, type);		\
	lh = 0;					\
	} while (0)

#define LISTFOREACH(lh, x)			\
	for (x = lh; x; x = x->next)

#ifdef __GNUC__
#define LISTEL(lh, no, type) ({			\
	int _i = 0;				\
	struct _list_##type *el;		\
	for (el = lh; el; ++_i, el = el->next)	\
		if (_i == no) break;		\
	el; })
#define LISTSIZE(lh,type) ({			\
	struct _list_##type *el;		\
	int _i = 0;				\
	for (el = lh; el; ++_i, el = el->next);	\
	_i; })
#else
/* TODO: create static inline functions ... */
#endif

#endif
