/***************************************************************************
  Name:         useful.c
  Description:  some useful code
  Created:      Sat Nov  6 17:09:45 EET 2004
  Copyright:    (C) 2004 by Kalle Kankare
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

#include "commonconf.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>

#include "iolet.h"
#include "useful.h"

/***************************************************************************
  Types
 ***************************************************************************/

/***************************************************************************
  Externals
 ***************************************************************************/

/***************************************************************************
  Internals
 ***************************************************************************/

/***************************************************************************
  Functions
 ***************************************************************************/

tvalue get_win_size(unsigned int *rows,unsigned int *cols)
{
  int ret;
  struct winsize win;

  ret = ioctl(0,TIOCGWINSZ,&win);

  *rows = win.ws_row;
  *cols = win.ws_col;

  if(ret == -1)
  {
    print_err("Error: Could not ioctl window's size: %s\n",strerror(errno));
    return FALSE;
  }

  return TRUE;
}

#ifndef HAVE_STRDUP

/* duplicate a string */
char *strdup(const char *string)
{
  char *palaute;
  unsigned int length;

  if(!string)
    return NULL;

  length = strlen(string);
  palaute = malloc(length + 1);

  if(palaute)
  {
    memcpy(palaute, string, length);
    palaute[length] = '\0';
  }
  else
    errno = ENOMEM;

  return palaute;
}
#endif /* HAVE_STRDUP */


#ifndef HAVE_STRNDUP

/* duplicate a string */
char *strndup(char *string, size_t length)
{
  register size_t beta;

  char *palaute;

  if(string == NULL || length == 0)
    return NULL;

  /* calculate the length */
  for(beta = 0; beta < length; beta++)
    if(string[beta] == 0)
    {
      length = beta + 1;
      break;
    }

  palaute = malloc(length + 1);

  if(palaute)
  {
    memcpy(palaute, string, length);
    palaute[length] = '\0';
  }
  else
    errno = ENOMEM;

  return palaute;
}
#endif /* HAVE_STRNDUP */


#ifndef HAVE_STRLCPY



#endif /* HAVE_STRLCPY */

void *use_malloc(size_t size)
{
  void *ptr;

  if((ptr = malloc(size)) == NULL)
    print_err("Error: Could not malloc() %zd bytes.\n", size);
  else
    return ptr;

  return NULL;
}

void *use_realloc(void *prevptr, size_t size)
{
  void *ptr;

  if((ptr = realloc(prevptr, size)) == NULL)
    print_err("Error: Could not realloc() %zd bytes.\n", size);
  else
    return ptr;

  return NULL;
}
