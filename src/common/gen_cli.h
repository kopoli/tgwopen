/***************************************************************************
  Name:         gen_cli.h
  Description:  a generic command-line interface
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

#ifndef PR_GEN_CLI_HEADER
#define PR_GEN_CLI_HEADER

#include "defines.h"
#include "getopt_clone.h"

/****************************************************************************
  Defines / Structures / data types
 ****************************************************************************/

/* flags for the gen_cli_argument */
#define GEN_CLI_CMDS_OPTIONAL 1
#define GEN_CLI_FLAGS_OPTIONAL 2

typedef struct 
{
	char *desc,*arg;
} gen_cli_helpstr;

typedef struct 
{
  /* the getopt option */
  option_clone *options;
  gen_cli_helpstr *help_strs;

} gen_cli_options;


typedef struct gen_cli_argument
{
  /* the command */
  char *cmd;

  int shortcmd;

  /* the command's parameters. For clarification purposes only */
  char *helpcmdparameter;

  /* possible argument after the command/options part. */
  char *helpcmdextra;

  /* the helptext for the command */
  char *cmdhelp;

  /* the options available for the command */
  gen_cli_options opt;

  /* subcommands */
  struct gen_cli_argument **subcmds;

  /* previous argument */
  struct gen_cli_argument *prev;

  unsigned int flags;

  /*
    The handling function of the parsed arguments. The ident is the identifier
    returned by getopt. parsefunc should return a negative value in case of 
    error and positive otherwise.

    In case of a negative value returned, gen_cli_parse_args returns with the
    same negative value.
   */
  int (*parsefunc)(int ident,int argc,char **argv,int getopt_ret);

} gen_cli_argument;


/****************************************************************************
  Prototypes
 ****************************************************************************/

/* Recursive help */
tvalue gen_cli_print_help(char *prog_name,gen_cli_argument *arg);

/* Handle the command-line. This function returns the negative value supplied by
  a parsefunc or 0 if something went wrong in the function. It returns the last
  positive return-value of a parsefunc when successful. If no arguments were 
  given this will return 1. */
int gen_cli_parse_args(gen_cli_argument *arg,int argc, char ** argv);


#endif
