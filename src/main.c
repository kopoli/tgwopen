/***************************************************************************
  Name:         main.c
  Description:  Command line interface definition and main()
  Created:      20070731 16:54
  Copyright:    (C) 2007 by Kalle Kankare
  Email:        kopoliitti@gmail.com

  **

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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <common/iolet.h>
#include <common/gen_cli.h>

#include "tgw.h"

/* the verbosity level */
unsigned int verbose=0;

static char *program_name=NULL;

static gen_cli_argument main_program;
static gen_cli_argument create_command;
static gen_cli_argument list_command;
static gen_cli_argument extract_command;

static char *archive=NULL;
static char *output_dir=NULL;
static name_list **files=NULL;

#define CMD_CREATE  1
#define CMD_LIST    2
#define CMD_EXTRACT 3
static char command=0;

/* **** **** */

static void print_help(char *name, gen_cli_argument *arg)
{
  gen_cli_print_help(name,arg);
  print_out("Send bug-reports to <%s>\n",PACKAGE_BUGREPORT);
}

static int create_command_parsefunc(int ident,int argc,char **argv,
  int getopt_ret)
{
  command=CMD_CREATE;

  /* the filenames */
  if(archive && getopt_ret == -3)
    files=name_list_add(files,strdup(optarg_clone));

  /* the archive name */
  if(getopt_ret == -3 && archive == NULL)
    archive=argv[argc];

  if(/* only command and no args */
     (getopt_ret == -1 && archive==NULL) ||
     (getopt_ret == 0 && ident == 0))
  {
    print_help(program_name,&create_command);
    return -2;
  }

  switch(ident)
  {
  case 1:
    verbose=1;
    break;
  default:
    break;
  }

  return 0;
}

static gen_cli_argument create_command =
{
  "create",
  'c',
  NULL,
  "<archive> [files ..]",
  "Create a new TGW-file.",
  {
    (option_clone [])
    {  
      {"help",'h',0,0},
      {"verbose",'V',0,1},
      {0,0,0}
    },
    (gen_cli_helpstr [])
    {
      {"Displays this help.",NULL },
      {"Increases verbosity.",NULL}
    }
  },
  NULL,
  &main_program,
  GEN_CLI_FLAGS_OPTIONAL,
  create_command_parsefunc
};

/* **** **** */

static int list_command_parsefunc(int ident,int argc,char **argv,
  int getopt_ret)
{
  command=CMD_LIST;
  /*
  print_out("ident on %d argc %d ja argv [%s] getopt %d\n",
    ident,argc,argv[argc],getopt_ret);
  */
  if(getopt_ret == -3 && archive == NULL)
    archive=argv[argc];

  if((getopt_ret == -1 && archive == NULL) ||
    (getopt_ret == 0 && ident == 0))
  {
    print_help(program_name,&list_command);
    return -2;
  }

  switch(ident)
  {
  case 1:
    verbose=1;
    break;
  default:
    break;
  }

  return 0;
}

static gen_cli_argument list_command =
{
  "list",
  'l',
  NULL,
  "<archive>",
  "List the contents of a TGW-file.",
  {
    (option_clone [])
    {  
      {"help",'h',0,0},
      {"verbose",'V',0,1},
      {0,0,0}
    },
    (gen_cli_helpstr [])
    {
      {"Displays this help.",NULL },
      {"Increases verbosity.",NULL}
    }
  },
  NULL,
  &main_program,
  GEN_CLI_FLAGS_OPTIONAL,
  list_command_parsefunc
};

/* **** **** */

static int extract_command_parsefunc(int ident,int argc,char **argv,
  int getopt_ret)
{
  command=CMD_EXTRACT;

  /* the filenames */
  if(archive && getopt_ret == -3)
    files=name_list_add(files,strdup(optarg_clone));

  if(getopt_ret == -3 && archive == NULL)
    archive=argv[argc];

  if((getopt_ret == -1 && archive == NULL) ||
    (getopt_ret == 0 && ident == 0))
  {
    print_help(program_name,&extract_command);
    return -2;
  }

  switch(ident)
  {
  case 2:
    output_dir=optarg_clone;
    break;
  case 1:
    verbose=1;
    break;
  default:
    break;
  }

  return 0;
}

static gen_cli_argument extract_command =
{
  "extract",
  'x',
  NULL,
  "<archive> [files ..]",
  "Extract the contents of a TGW-file.",
  {
    (option_clone [])
    {  
      {"output-dir",'o',1,2},
      {"help",'h',0,0},
      {"verbose",'V',0,1},
      {0,0,0}
    },
    (gen_cli_helpstr [])
    {
      {"Extracts contents to directory <dir>.","<dir>"},
      {"Displays this help.",NULL },
      {"Increases verbosity.",NULL}
    }
  },
  NULL,
  &main_program,
  GEN_CLI_FLAGS_OPTIONAL,
  extract_command_parsefunc
};

/* **** **** */

static int main_program_parsefunc(int ident,int argc,char **argv,
  int getopt_ret)
{
  if(getopt_ret == -1 || getopt_ret == -3)
    ident=0;

  switch(ident)
  {
  case 0:
    print_help(program_name,&main_program);
    return -2;
  case 12:
    print_out(PACKAGE_NAME " v." PACKAGE_VERSION "\n");
    return -2;
  default:
    break;
  }
  return -1;
}

static gen_cli_argument main_program =
{
  NULL,
  0,
  NULL,
  NULL,
  PACKAGE_NAME " is used to open, create and list TGW-files.",
  {
    (option_clone [])
    {  
      {"help",'h',0,0},
      {"version",'v',0,12},
      {0,0,0}
    },
    (gen_cli_helpstr [])
    {
      {"Displays this help.",NULL },
      {"Displays the version.",NULL}
    }
  },

  (struct gen_cli_argument *[])
    {&create_command,&list_command,&extract_command,NULL},
  NULL,
  GEN_CLI_FLAGS_OPTIONAL,
  main_program_parsefunc
};

int main(int argc, char **argv)
{ 
  int ret;
  program_name=argv[0];
  tgw_file *arch=NULL;

  if(argc == -1)
  {
    print_help(program_name,&main_program);
    return 0;
  }

  /* the command line args */
  if((ret=gen_cli_parse_args(&main_program,argc,argv)) < 0)
  {
    if(ret == -2)  /* help and usage */
      return 0;

    return 1;
  }

  /* the execution */
  if(command == CMD_LIST)
  {
    arch=tgw_file_read_headers(archive);
    if(!arch)
      return 1;

    tgw_file_list(arch,(uint8_t)verbose);

    tgw_file_free(arch);
    arch=NULL;
    return 0;
  }

  if(command == CMD_EXTRACT)
  {
    arch=tgw_file_read_headers(archive);
    if(!arch)
      return 1;

    if(!tgw_file_extract(arch,files,output_dir))
      return 1;

    tgw_file_free(arch);
    arch=NULL;

    name_list_free(files);

    return 0;    
  }

  if(command == CMD_CREATE)
  {
    int file;

    if(!archive)
    {
      print_err("Error: archive name is required.\n");
      return 1;
    }
    if(!files)
    {
      print_err("Error: filenames are required.\n");
      return 1;
    }

    if((file=open(archive,O_CREAT|O_WRONLY|O_TRUNC,0644)) == -1)
    {
      print_err("Error creating archive \"%s\": %s\n",archive, 
        strerror(errno));
      name_list_free(files);
      return 1;
    }

    if(tgw_file_create(file,files) == 0)
      return 1;

    close(file);

    name_list_free(files);
    return 0;
  }

  return 0;
}
