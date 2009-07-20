/***************************************************************************
  Name:         getopt_clone.h
  Description:  A bastardisation of getopt_long and whatnot.
  Created:      Sun May 23 14:35:55 EEST 2004
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

#ifndef PR_GETOPT_OWN_HEADER
#define PR_GETOPT_OWN_HEADER

/****************************************************************************
  Defines / Structures / data types
 ****************************************************************************/

/* for has_arg variable in option_clone */
#define GETOPT_NO_ARGUMENT        0
#define GETOPT_REQUIRED_ARGUMENT  1
#define GETOPT_OPTIONAL_ARGUMENT  2

typedef struct option_clone
{
  char *longflag;         /* long flag usually preceded by -- */
  int shortflag;          /* short flag preceded by - */
  unsigned int has_arg;   /* 3 possible values */

  int identifier;         /* the identifier which is unique for each option 
                             and != 0 */
} option_clone;

extern char *optarg_clone;
extern unsigned int optarg_pos_clone;

/****************************************************************************
  Prototypes
 ****************************************************************************/

/* the return codes of extraordinary situations */
#define GETOPT_RETURN_FAILURE   -2  /* something cracked */
#define GETOPT_RETURN_LAST      -1  /* there are no more arguments */
#define GETOPT_RETURN_NORMAL    -3  /* the argument is not a flag */

#define GETOPT_RETURN_FLAG       0

int getopt_clone(const int argc, char * const argv[], 
  option_clone *opts, int *identifier);

#endif
