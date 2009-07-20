/***************************************************************************
  Name:         iolet.c
  Description:  Common low-level input and output layer
  Created:      Thu Dec 18 23:43:30 EET 2003
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
#include "commonconf.h"

#include <stdio.h>
#include <string.h>

#include "llist.h"
#include "iolet.h"

/***************************************************************************
  Types
 ***************************************************************************/

/***************************************************************************
  Externals
 ***************************************************************************/

iolet *IL_IOStd = NULL;
iolet *IL_OutErr = NULL;
iolet *IL_OutDebug = NULL;

const char *ARGERROR_STR = 
  "Bad arguments for function \"%s\" at %s:%d, assertion"
  " \"%s\" failed.\n";

/***************************************************************************
  Internals
 ***************************************************************************/

/* List of iolets. */
static linked_list *IOletList = NULL;

/* Has this system been initialized */
static tvalue iolet_initialized = FALSE;


/***************************************************************************
  Functions
 ***************************************************************************/

/***************************************************************************
  Standard input and output
 ***************************************************************************/

static iolet StdIO;
const iolet *IL_DefIOStd = &StdIO;
const iolet *IL_DefOutDebug = &StdIO;

/* just a trick to prevent warning when compiling with gcc -W */
#if defined __GNUC__
# define UNUSED __attribute__((unused))
#else
# define UNUSED 
#endif /* __GNUC__ */


static int StdIn_InputChar(struct iolet *in UNUSED)
{
  int khar;

  khar = fgetc(stdin);

  if(khar == EOF)
    return -1;

  return khar;
}

static tvalue StdIn_InputLine(struct iolet *in UNUSED, char *line, size_t length)
{
  if(!line)
    return FALSE;

  if(fgets(line, length, stdin) == NULL)
    return FALSE;

  return TRUE;
}

static tvalue StdIn_InputStream(struct iolet *in UNUSED, char *data, size_t length)
{
  size_t check = 0;

  if(!data)
    return FALSE;

  /* hmm.. is this wasteful? */
  check = fread(data, 1, length, stdin);
  if(check != length)
    return FALSE;

  return TRUE;
}

static tvalue StdIn_IsEof(struct iolet *in UNUSED)
{
  if(feof(stdin) != 0)
    return TRUE;

  return FALSE;
}


static tvalue StdOut_Output(iolet * out UNUSED, const char *format, va_list ap)
{
  int returni = vfprintf(stdout, format, ap);
  if(returni < 0)
    return FALSE;
  return TRUE;
}

static tvalue StdOut_OutputChar(struct iolet *out UNUSED, int khar)
{
  if(fputc(khar,stdout) == EOF)
    return FALSE;
  else 
    return TRUE;
}

static tvalue StdOut_OutputStream(struct iolet * out UNUSED, 
  const char *data, size_t length)
{
  int returni = fwrite(data,1,length,stdout);

  if(returni < 0)
    return FALSE;

  return TRUE;
}

static inline tvalue StdIO_End(iolet * out UNUSED)
{
  return TRUE;
}

/* Create the iolet */
static inline tvalue AddStdIO()
{
  /* Input */
  StdIO.InputChar = (*StdIn_InputChar);
  StdIO.InputLine = (*StdIn_InputLine);
  StdIO.InputStream = (*StdIn_InputStream);
  StdIO.IsEof = (*StdIn_IsEof);

  /* Output */
  StdIO.OutputFormat = (*StdOut_Output);
  StdIO.OutputStream = (*StdOut_OutputStream);
  StdIO.OutputChar = (*StdOut_OutputChar);

  StdIO.End = (*StdIO_End);

  StdIO.PrivData = NULL;
  StdIO.PDataLen = 0;
  StdIO.Type = IL_IOLET_TERMINAL;
  StdIO.Flags =
   IL_INLET_CHAR | IL_INLET_LINE | IL_INLET_STREAM | IL_OUTLET_FORMAT | 
   IL_OUTLET_CHAR | IL_OUTLET_STREAM;

  return iolet_add(&StdIO);
}

/***************************************************************************
  Standard error output
 ***************************************************************************/

static iolet StdErr;
const iolet *IL_DefOutErr = &StdErr; /* This is visible externally */

static tvalue StdErr_Output(iolet * out UNUSED, const char *format, va_list ap)
{
  int returni = vfprintf(stderr, format, ap);
  if(returni < 0)
    return FALSE;
  return TRUE;
}

static tvalue StdErr_OutputChar(struct iolet *out UNUSED, int khar)
{
  if(fputc(khar,stderr) == EOF)
    return FALSE;
  else 
    return TRUE;
}

static inline tvalue StdErr_End(iolet * out UNUSED)
{
  return TRUE;
}

/* This makes the outlet available */
static inline tvalue AddStdErr()
{
  /* no input for stderr */
  StdErr.InputChar = NULL;
  StdErr.InputLine = NULL;
  StdErr.InputStream = NULL;
  StdErr.IsEof = NULL;

  StdErr.End = (*StdErr_End);
  StdErr.OutputFormat = (*StdErr_Output);
  StdErr.OutputStream = NULL;
  StdErr.OutputChar = StdErr_OutputChar;

  StdErr.PrivData = NULL;
  StdErr.PDataLen = 0;
  StdErr.Flags = IL_OUTLET_FORMAT | IL_OUTLET_CHAR;
  StdErr.Type = IL_IOLET_TERMINAL;

  return iolet_add(&StdErr);
}

/***************************************************************************
  IOlet system management
 ***************************************************************************/

void iolet_deinit(void)
{
  linked_list_cell *pos=NULL;
  iolet *This = NULL;

  if(iolet_initialized == FALSE)
    return;

  /* End all iolets */
  linked_list_use_error = FALSE;
  while((pos=linked_list_cycle(IOletList, pos)) != NULL)
  {
    This=pos->Data;

    /* Let the outlet take care of itself */
    if(This->End != NULL)
      This->End(This);
  }
  linked_list_use_error = TRUE;

  /* Delete the list */
  linked_list_delete(IOletList);
  IOletList = NULL;

  /* Make sure that these are not available */
  IL_IOStd = NULL;
  IL_OutErr = NULL;
  IL_OutDebug = NULL;

  iolet_initialized = FALSE;
}

tvalue iolet_init()
{
  /* Don't want to initialize this twice */
  if(iolet_initialized == TRUE)
    return TRUE;

  /* Do the necessary mangling for iolet_add */
  linked_list_use_error = FALSE;
  IOletList = linked_list_create();
  linked_list_use_error = TRUE;
  if(IOletList == NULL)
    return FALSE;

  /* Create the default iolets */
  if(!AddStdIO() || !AddStdErr())
    return FALSE;

  IL_IOStd = &StdIO;
  IL_OutErr = &StdErr;
  IL_OutDebug = &StdIO;

  /* Make sure that this is executed */
  atexit(iolet_deinit);

  iolet_initialized = TRUE;
  return TRUE;
}

/* Add an iolet into the system */
tvalue iolet_add(iolet * IO)
{
  if(!IO || !IOletList)
    return FALSE;

  /* Add the iolet */
  linked_list_use_error = FALSE;
  if(linked_list_add_data(IOletList, IO) == FALSE)
  {
    linked_list_use_error = TRUE;
    return FALSE;
  }
  linked_list_use_error = TRUE;

  return TRUE;
}

/* Delete an iolet from the system */
tvalue iolet_del(iolet * IO)
{
  if(!IO || !IOletList)
    return FALSE;

  /* It would be bad to fsck up the default iolets */
  if(IO == IL_DefIOStd || IO == IL_DefOutErr)
    return TRUE;

  /* Delete the iolet from the list */
  linked_list_use_error = FALSE;
  if(linked_list_delete_data(IOletList, IO) == FALSE)
  {
    linked_list_use_error = TRUE;
    return FALSE;
  }

  /* Delete the iolet */
  if(IO->End(IO) == FALSE)
    return FALSE;

  return TRUE;
}

/***************************************************************************
  Outputting
 ***************************************************************************/

static const char *ERR_NOFORMAT_OUT =
 "Error: Formatted output failed; " "iolet lacks format outputmethod.\n";

/* Outputting formatted output to outlet Out */
tvalue iolet_out_format(iolet * Out, const char *Format, ...)
{
  va_list lista;
  tvalue returni;

  if(!Out || !Format)
    return FALSE;

  /* Theoretically this is a charade if this module has not been initalized. */
  if(iolet_initialized == FALSE)
    return FALSE;

  /* Variable argument list outputmethod must be available */
  if((Out->Flags & IL_OUTLET_FORMAT) == FALSE)
  {
    fputs(ERR_NOFORMAT_OUT,stderr);
    return FALSE;
  }

  va_start(lista, Format);
  returni = Out->OutputFormat(Out, Format, lista);
  va_end(lista);

  return returni;
}

/* Same as above but only with a va_list. */
tvalue iolet_out_format_v(iolet * Out, const char *Format, va_list Args)
{
  if(!Out || !Format)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  /* Variable argument list outputmethod must be available */
  if((Out->Flags & IL_OUTLET_FORMAT) == FALSE)
  {
    fputs(ERR_NOFORMAT_OUT,stderr);
    return FALSE;
  }

  return Out->OutputFormat(Out, Format, Args);
}


/* Output a buffer into outlet Out */
tvalue iolet_out_stream(iolet * Out, const char *Data, size_t Length)
{
  tvalue returni;

  if(!Out || !Data)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  if((Out->Flags & IL_OUTLET_STREAM) == FALSE)
  {
    fprintf(stderr,
     "Error: Streamed output failed; iolet lacks stream" " outputmethod.\n");
    return FALSE;
  }

  returni = Out->OutputStream(Out, Data, Length);
  return returni;
}

tvalue iolet_out_char(struct iolet * Out, int khar)
{
  if(!Out)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  if((Out->Flags & IL_OUTLET_CHAR) == FALSE)
  {
    fprintf(stderr,
     "Error: Streamed output failed; iolet lacks character outputmethod.\n");
    return FALSE;
  }
  
  return Out->OutputChar(Out,khar);
}


/* Default printing */
tvalue print_out(const char *format, ...)
{
  tvalue returni = FALSE;
  va_list lista;

  /* If the default iolets do not exist, make them */
  if(iolet_init() == FALSE)
    return FALSE;

  va_start(lista, format);
  returni = iolet_out_format_v(IL_IOStd, format, lista);
  va_end(lista);

  return returni;
}

/* Printing to stderr (or some substituted iolet) */
tvalue print_err(const char *format, ...)
{
  tvalue returni = FALSE;
  va_list lista;

  if(iolet_init() == FALSE)
    return FALSE;

  va_start(lista, format);
  returni = iolet_out_format_v(IL_OutErr, format, lista);
  va_end(lista);

  return returni;
}

#ifdef DEBUG
/* Default printing */
tvalue print_debug(const char *format, ...)
{
  tvalue returni = FALSE;
  va_list lista;

  /* If the default iolets do not exist, make them */
  if(iolet_init() == FALSE)
    return FALSE;

  va_start(lista, format);
  returni = iolet_out_format_v(IL_OutDebug, format, lista);
  va_end(lista);

  return returni;
}
/* if the compiler is incapable to use variable arguments in macros */
#elif __STDC_VERSION__ < 199901L
tvalue print_debug(const char *format, ...)
{
  format=format;
  return TRUE;
}
#endif

/***************************************************************************
  Inputting
 ***************************************************************************/

char iolet_in_char(iolet * In)
{
  if(!In)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  if((In->Flags & IL_INLET_CHAR) == FALSE)
  {
    fprintf(stderr,
     "Error: Character input failed; iolet lacks character" " inputmethod.\n");
    return 0;
  }

  return In->InputChar(In);
}

tvalue iolet_in_line(iolet * In, char *Line, size_t Length)
{
  if(!In || !Line)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  if((In->Flags & IL_INLET_LINE) == FALSE)
  {
    print_err("Error: Character input failed; iolet lacks line"
     " inputmethod.\n");
    return 0;
  }

  return In->InputLine(In, Line, Length);
}

tvalue iolet_in_stream(iolet * In, char *Data, size_t Length)
{
  if(!In || !Data)
    return FALSE;

  if(iolet_initialized == FALSE)
    return FALSE;

  if((In->Flags & IL_INLET_STREAM) == FALSE)
  {
    print_err("Error: Character input failed; iolet lacks line"
     " inputmethod.\n");
    return 0;
  }

  return In->InputStream(In, Data, Length);
}

tvalue iolet_in_eof(iolet * In)
{
  /* If the inlet does not exist, then it is in EOF */
  /* This probably is a bad idea */
  if(!In)
    return TRUE;

  if(iolet_initialized == FALSE)
    return TRUE;

  return In->IsEof(In);
}

/* Input through the default inlet */
char iolet_get_char()
{
  if(iolet_init() == FALSE)
    return 0;

  return iolet_in_char(IL_IOStd);
}

tvalue iolet_get_line(char *Line, size_t Length)
{
  if(iolet_init() == FALSE)
    return FALSE;

  return iolet_in_line(IL_IOStd, Line, Length);
}

tvalue iolet_get_stream(char *Data, size_t Length)
{
  if(iolet_init() == FALSE)
    return FALSE;

  return iolet_in_stream(IL_IOStd, Data, Length);
}

tvalue iolet_get_eof()
{
  if(iolet_init() == FALSE)
    return FALSE;

  return IL_IOStd->IsEof(IL_IOStd);
}

/***************************************************************************
  IOlet duplication
 ***************************************************************************/

typedef struct
{
  iolet *First;
  iolet *Second;
} ioletDuo;

static tvalue Duo_Output_Format(iolet * io, const char *format, va_list list)
{
  ioletDuo *tmp;
  if(io->PDataLen != sizeof(ioletDuo))
    return FALSE;

  tmp = io->PrivData;

  /* Do the formatted output for both */
  if(tmp->First->Flags & IL_OUTLET_FORMAT)
    if(tmp->First->OutputFormat(tmp->First, format, list) == FALSE)
      return FALSE;

  if(tmp->Second->Flags & IL_OUTLET_FORMAT)
    if(tmp->Second->OutputFormat(tmp->Second, format, list) == FALSE)
      return FALSE;

  return TRUE;
}

static tvalue Duo_Output_Stream(iolet * io, const char *data, size_t length)
{
  ioletDuo *tmp;
  if(io->PDataLen != sizeof(ioletDuo))
    return FALSE;

  tmp = io->PrivData;

  if(tmp->First->Flags & IL_OUTLET_STREAM)
    if(tmp->First->OutputStream(tmp->First, data, length) == FALSE)
      return FALSE;

  if(tmp->Second->Flags & IL_OUTLET_STREAM)
    if(tmp->Second->OutputStream(tmp->Second, data, length) == FALSE)
      return FALSE;

  return TRUE;
}

/* Only end this pseudo-outlet and not the originals. */
static tvalue Duo_End(iolet * io)
{
  if(io->PDataLen != sizeof(ioletDuo))
    return FALSE;

  nullify(io->PrivData);
  nullify(io);
  return TRUE;
}

iolet *iolet_fork_output(iolet * First, iolet * Second)
{
  iolet *outti;
  ioletDuo *tmp;

  if(!First || !Second)
    return NULL;

  outti = malloc(sizeof(iolet));
  if(!outti)
  {
    print_err("Error: Could not allocate %d bytes.\n", sizeof(iolet));
    return NULL;
  }

  outti->PrivData = malloc(sizeof(ioletDuo));
  if(!outti->PrivData)
  {
    print_err("Error: Could not allocate %d bytes.\n", sizeof(ioletDuo));
    return NULL;
  }

  /* Set the necessary values */
  outti->PDataLen = sizeof(ioletDuo);
  tmp = outti->PrivData;
  tmp->First = First;
  tmp->Second = Second;

  /* This probably should be checked */
  outti->Flags = IL_OUTLET_FORMAT | IL_OUTLET_STREAM;

  /* And the "methods" */
  outti->OutputFormat = Duo_Output_Format;
  outti->OutputStream = Duo_Output_Stream;

  /* No input */
  outti->InputChar = NULL;
  outti->InputLine = NULL;
  outti->InputStream = NULL;
  outti->IsEof = NULL;

  outti->End = Duo_End;

  iolet_add(outti);

  return outti;
}

/***************************************************************************
  IOlet data copying
 ***************************************************************************/

/* copies all data from from to to. */
/* A stream input and output is required */
tvalue iolet_copy_data(iolet *From,iolet *To)
{
  const unsigned int BUFLEN = 256;

  unsigned int length;
  char temp[BUFLEN];
  char *errstr = "Error: Copying data from inlet to outlet failed.\n";
  tvalue loppu=FALSE;

  if(!From || !To)
    return FALSE;

  /* stream output and inputmethods are required */
  if(!(From->Flags | IL_INLET_STREAM) || !(To->Flags | IL_OUTLET_STREAM))
    return FALSE;

  while(1)
  {
    /* read enough data from iolet */
    memset(temp,0,BUFLEN);
    if(iolet_in_stream(From,temp,BUFLEN) == FALSE)
    {
      if(iolet_in_eof(From) == FALSE)
      {
        print_err(errstr);
        return FALSE;
      }
      loppu=TRUE;
    }

    /* determine the length */
    if(temp[BUFLEN-1] != 0)
      length=BUFLEN;
    else
      length=strlen(temp);

    /* write to the appropriate place */
    if(iolet_out_stream(To,temp,length) == FALSE)
    {
      print_err(errstr);
      return FALSE;
    }

    if(loppu == TRUE)
      break;
  }

  return TRUE;
}
