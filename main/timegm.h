#ifndef __TIMEGM__H
#define __TIMEGM__H

#ifndef HAVE_TIMEGM

#include <time.h>

time_t timegm(struct tm *tm);
#endif

#endif
