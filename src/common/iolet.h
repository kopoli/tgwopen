/***************************************************************************
  Name:         iolet.h
  Description:  Common low-level input and output layer
  Created:      Tue Nov 25 16:29:21 EET 2003
  Copyright:    (C) 2003 by Kalle Kankare
  Email:        kopoliitti@gmail.com
 ***************************************************************************/

/***************************************************************************

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 ***************************************************************************/

/****************************************************************************
  Notes
  -The name comes from coalition of inlets and outlets. There was two 
   separate layers before.

 ****************************************************************************/

#ifndef IL_IOLET_HEADER
#define IL_IOLET_HEADER

#include "commonconf.h"

#include <stdlib.h>
#include <stdarg.h>

/****************************************************************************
  Defines / Structures / data types
 ****************************************************************************/

/* The IOlet type. The values are below */
typedef unsigned char iolet_type;

/* Types of iolets */
#define IL_IOLET_TERMINAL        1  /* Normal terminal input and output */
#define IL_IOLET_FILE            2  /* File in a filesystem */
#define IL_IOLET_SOCKET          3  /* A network socket */

/* Flags for iolets */
#define IL_OUTLET_FORMAT    1
#define IL_OUTLET_STREAM    2
#define IL_OUTLET_CHAR      4
#define IL_INLET_CHAR       8
#define IL_INLET_LINE       16
#define IL_INLET_STREAM     32

/* Common interface for input and output */
typedef struct iolet
{
  void *PrivData;               /* A pointer to some context dependant data. */
  size_t PDataLen;              /* The length of the data itself. */
  iolet_type Type;            /* Type as explained above. */
  flagtype Flags;                /* Possible flags of the iolet. */

  /* Output functionality */
  tvalue(*OutputFormat) (struct iolet * out, const char *format,
    va_list list);
  tvalue(*OutputStream) (struct iolet * out, const char *data,
    size_t length);
  tvalue(*OutputChar) (struct iolet * out, int khar);

  /* Input functionality */
  int (*InputChar) (struct iolet * in); /* Inputting one character */

  /* Input one line to buffer line or max length bytes */
  tvalue(*InputLine) (struct iolet * in, char *line, size_t length);

  /* Try to read length bytes from inlet and write it to data */
  tvalue(*InputStream) (struct iolet * in, char *data, size_t length);

  /* Checks if the stream has reached its end */
  tvalue(*IsEof) (struct iolet * in);

  /* Termination */
  tvalue(*End) (struct iolet * io);

} iolet;


/* Standard iolets  */
extern iolet *IL_IOStd;
extern iolet *IL_OutErr;
extern iolet *IL_OutDebug;

/* The const pointers to the original standard iolets */
extern const iolet *IL_DefIOStd;
extern const iolet *IL_DefOutErr;
extern const iolet *IL_DefOutDebug;

/****************************************************************************
  Prototypes
 ****************************************************************************/


/* System management */
tvalue iolet_init();
void iolet_deinit(void);

/* IOlet management */
tvalue iolet_add(iolet * IO);
tvalue iolet_del(iolet * IO);

/* Output functions */
tvalue iolet_out_format(iolet * Out, const char *Format, ...);
tvalue iolet_out_format_v(iolet * Out, const char *Format, va_list Args);
tvalue iolet_out_stream(iolet * Out, const char *Data, size_t Length);
tvalue iolet_out_char(struct iolet * Out, int khar);

/* Output through default outlets */
tvalue print_out(const char *format, ...);
tvalue print_err(const char *format, ...);

#if (defined DEBUG) || (!defined DEBUG && (__STDC_VERSION__ < 199901L))
tvalue print_debug(const char *format, ...);
#else
# define print_debug(format, ...) 
#endif

/* Input functions */
char iolet_in_char(iolet * In);
tvalue iolet_in_line(iolet * In, char *Line, size_t Length);
tvalue iolet_in_stream(iolet * In, char *Data, size_t Length);
tvalue iolet_in_eof(iolet * In);

/* Input through the default inlet */
char iolet_get_char();
tvalue iolet_get_line(char *Line, size_t Length);
tvalue iolet_get_stream(char *Data, size_t Length);
tvalue iolet_get_eof();

/* Outlet duplication. It would make no sense to gather input from two sources 
 */
iolet *iolet_fork_output(iolet * First, iolet * Second);

/* copies all data from from to to. */
/* A stream input and output is required */
tvalue iolet_copy_data(iolet *From,iolet *To);

extern const char *ARGERROR_STR;

#ifdef ASSERTION_REPORT

# undef ARG_ASSERT
# define ARG_ASSERT(assertion,retval) \
    if((assertion)) \
    { \
      print_err(ARGERROR_STR,THIS_FUNCTION,__FILE__,__LINE__, \
        #assertion); \
      return retval; \
    }

#endif

#endif
