/***************************************************************************
  Name:         getopt_clone.c
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

#include "commonconf.h"

#include <string.h>

#include "iolet.h"
#include "getopt_clone.h"

/***************************************************************************
  Types
 ***************************************************************************/

/***************************************************************************
  Externals
 ***************************************************************************/

char *optarg_clone=NULL;

/* usually the position in argv which holds the string 
  pointed to by optarg_clone */
unsigned int optarg_pos_clone=0;

/***************************************************************************
  Internals
 ***************************************************************************/

/* getopt_clone assumes that SHORT_FLAG is shorter than LONG_FLAG */
static const char *SHORT_FLAG = "-";
#define SHORT_FLAG_LENGTH 1

static const char *LONG_FLAG = "--";
#define LONG_FLAG_LENGTH  2

/* the internal variable to mark the last handled argument +1 */
#define NEXTPOS_START 1
static unsigned int nextpos=NEXTPOS_START;

/* the position in a cluster of short flags (-abcd) */
static int shortchained=0;

/***************************************************************************
  Functions
 ***************************************************************************/

static char *construct_flag(option_clone *opt)
{
  char *str=NULL;  
  unsigned int length=1;
  char *prefix=(char *)SHORT_FLAG;
  tvalue uselong=FALSE;

  if(opt->longflag != NULL)
  {
    length+=LONG_FLAG_LENGTH+strlen(opt->longflag);
    prefix=(char *)LONG_FLAG;
    uselong=TRUE;
  }  
  else
    length+=SHORT_FLAG_LENGTH+1;

  str=malloc(length);
  if(!str)
  {
    print_err("Error: Ran out of memory in getopt_clone while constructing a"
      " flag representation.\n");
    return NULL;
  }

  memset(str,0,length);
  strcat(str,prefix);
  if(uselong==TRUE)
    strcat(str,opt->longflag);
  else
  {
    unsigned int pos=strlen(str);
    str[pos] = opt->shortflag;
    str[pos+1] = 0;
  }

  return str;
}

static tvalue determine_arg(const int argc, char * const argv[], 
  option_clone *opt)
{
  char *cur;
  optarg_clone = NULL;
  nextpos++;

  if(!opt)
    return FALSE;

  /* no argument is requested */
  if(opt->has_arg == GETOPT_NO_ARGUMENT)
  {
    nextpos--;
    return TRUE;
  }

  else if(opt->has_arg != GETOPT_REQUIRED_ARGUMENT && 
    opt->has_arg != GETOPT_OPTIONAL_ARGUMENT)
  {
    print_err("Error: The option_clone -struct supplied has invalid has_arg"
      " variable.\n");
    return FALSE;
  }

  /* check if the flag was the last argument */
  if(nextpos == (unsigned int) argc) 
  {
    if(opt->has_arg == GETOPT_REQUIRED_ARGUMENT)
    {
      char *str = construct_flag(opt);
      if(!str)
        return FALSE;

      print_err("Error: The last flag \"%s\" is supposed to have an"
        " argument.\n",str);

      nullify(str);
      return FALSE;
    }
    return TRUE;
  }

  cur = argv[nextpos];  

  /* check if this really is a flag */
  if(strncmp(cur,LONG_FLAG,LONG_FLAG_LENGTH) == 0 || 
     strncmp(cur,SHORT_FLAG,SHORT_FLAG_LENGTH) == 0)
  {
    if(opt->has_arg == GETOPT_REQUIRED_ARGUMENT)
    {
      char *str = construct_flag(opt);
      if(!str)
        return FALSE;

      print_err("Error: The flag \"%s\"  is supposed to have an argument.\n",
        str);

      nullify(str);
      return FALSE;
    }
    return TRUE;
  }

  optarg_clone=cur;
  return TRUE;
}

/*
  getopt_clone()

  Notes:
  -The first element of argv is ignored as it usually is the name of the 
   program.

  Assumptions:
  -In internals-section check the description of SHORT_ and LONG_ FLAGs.
*/


int getopt_clone(const int argc, char *const argv[], 
  option_clone *opts, int *identifier)
{
  char *cur;
  register unsigned int beta=0;
  int pos=GETOPT_RETURN_FAILURE;
  unsigned int optcount=0;

  ARG_ASSERT(argc < 0 || !argv || !opts || !identifier,GETOPT_RETURN_FAILURE);

  *identifier=0;

  /* Let's restart the nextpos if there is no more arguments */
  if(nextpos == (unsigned int)argc)
  {
    nextpos = NEXTPOS_START;
    return GETOPT_RETURN_LAST;
  }

  cur=argv[nextpos];

  /* count the number of opts */
  for(optcount=0;
      opts[optcount].longflag!=NULL && opts[optcount].shortflag!=0;
      optcount++)
    ;

  /* check if it is a long flag */
  if(strncmp(cur,LONG_FLAG,LONG_FLAG_LENGTH) == 0)
  {
    cur+=LONG_FLAG_LENGTH;

    /* check if a long option is in opts */
    for(beta=0;beta<optcount;beta++)
      if(strcmp(cur,opts[beta].longflag) == 0)
      {
        pos=(signed int)beta;
        break;
      }

    /* check if nothing was found */
    if(pos == GETOPT_RETURN_FAILURE)
    {
      print_err("Error: Unknown long-flag: \"%s\" was found.\n",
        cur-LONG_FLAG_LENGTH);
      return pos;
    }
    /* determine possible arguments */
    else if(determine_arg(argc,argv,&opts[beta]) == FALSE)
      pos=GETOPT_RETURN_FAILURE;
      
  }
  /* a short flag */
  else if(strncmp(cur,SHORT_FLAG,SHORT_FLAG_LENGTH) == 0)
  {
    cur+=SHORT_FLAG_LENGTH;

    for(beta=0;beta<optcount;beta++)
      if(opts[beta].shortflag == cur[shortchained])
      {
        pos=beta;

        /* check if last in the cluster */
        if(shortchained == (signed int)(strlen(cur)-1))
        {
          if(determine_arg(argc,argv,&opts[beta]) == FALSE)
            pos=GETOPT_RETURN_FAILURE;
          shortchained=-1;
        }
        /* check if this is in the middle of the cluster and should have 
           an argument. */
        else if(opts[beta].has_arg == GETOPT_REQUIRED_ARGUMENT)
        {
          char *str = construct_flag(&opts[beta]);
          pos=GETOPT_RETURN_FAILURE;
          if(str)
            print_err("Error: Short-flag \"%s\" should have"
              " an argument.\n",str);
          nullify(str);            
        }

        else
          nextpos--;

        break;
      }   
    shortchained++; 
  }
  /* a normal argument */
  else
  {
    optarg_clone = cur;
    optarg_pos_clone = nextpos;
    pos=GETOPT_RETURN_NORMAL;
  }

  nextpos++;

  *identifier=0;

  if(pos == GETOPT_RETURN_FAILURE || pos == GETOPT_RETURN_NORMAL)
    return pos;

  *identifier=opts[pos].identifier;

  return GETOPT_RETURN_FLAG;
}

//#define GETOPT_OWN_DEBUG
#ifdef GETOPT_OWN_DEBUG

option_clone piip[] = 
{
  {"hippi",'h',0 },
  {"kuppi",'k',0 },
  {"nappi",'z',2 },
  {"qööäåö",'q',1 },
  {0,0,0 }
};

int main(int argc, char **argv)
{
  int ret;

  while((ret=getopt_clone(argc,argv,piip)) != GETOPT_RETURN_LAST)
  {
    if(ret == GETOPT_RETURN_FAILURE)
      return 1;

    else if(ret == GETOPT_RETURN_NORMAL)
    {
      print_out("Normal parameter at pos %d: \"%s\"\n",nextpos,
        optarg_clone);
    }
    else
    {
      print_out("Flag argument at pos %d: %d\"--%s\"",nextpos,ret,
        piip[ret].longflag);
      if(optarg_clone)
        print_out(" with argument \"%s\"",optarg_clone);
      print_out("\n");
    }
  }
  return 0;
}

#endif
