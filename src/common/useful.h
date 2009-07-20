/***************************************************************************
  Name:         useful.h
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

#ifndef PR_COMMON_HEADER
#define PR_COMMON_HEADER

tvalue get_win_size(unsigned int *rows,unsigned int *cols);

#ifndef HAVE_STRDUP
char *strdup(const char *string);
#endif

#ifndef HAVE_STRNDUP
char *strndup(char *string, unsigned int length);
#endif

void *use_malloc(size_t size);
void *use_realloc(void *prevptr, size_t size);

#endif
