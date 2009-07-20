/* some very common types and conventions */

#ifndef DEFINES_HEADER
#define DEFINES_HEADER

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Something for the *!# compiler */
#ifdef _MSC_VER
# include "msvc.h"
#endif

/* The truth value type */
typedef unsigned char tvalue;

/* The truth values */
#ifdef  TRUE
# undef TRUE
#endif

#ifdef  FALSE
# undef FALSE
#endif

#define FALSE ((tvalue)(0))
#define TRUE  (!FALSE)

/* safe memory deletion */
#define nullify(m) do { if(m) free(m); m=NULL; } while(0)

/* Dealing with bad arguments */
#define ARG_ASSERT(assertion,retval) \
  do { if((assertion)) return retval; } while(0)

/* Getting the function name */
#if (defined __GNUC__) && __GNUC__ >= 2
# define THIS_FUNCTION ((char *)__func__)
#elif (defined __func__)
# define THIS_FUNCTION __func__
#else
# define THIS_FUNCTION ("Some function in " __FILE__ " near line " __LINE__)
#endif

#endif
