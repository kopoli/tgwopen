/*
  TGW-file handling functions.

  tgw.c and tgw.h, 2007, 2009 
  public domain.
*/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>

#include <common/defines.h>
#include <common/iolet.h>

#define TGW_INTERNAL

#include "tgw.h"

extern unsigned int verbose;

static const char mkdir_cmd[] = "/bin/mkdir -p '%s/%s'";
#define mkdir_cmd_len (sizeof(mkdir_cmd))
#define cmd_str_len (FILENAME_MAX+mkdir_cmd_len+1)
static char cmd_str[cmd_str_len];

static int mkdir_p(char *base,char *path)
{
  if(!path)
    return 0;

  snprintf(cmd_str,cmd_str_len,mkdir_cmd,base,path);

  if(system(cmd_str))
    return 0;

  return 1;
}

#define crash_burn(s,...)                       \
  do {                                          \
    print_err("Error: ");                       \
    print_err(s, ##__VA_ARGS__);                \
    print_err("\n");                            \
    goto badend;                                \
  }while(0)

static int extract_file(int file,char *tofile,
  uint8_t *buffer,uint32_t offset, uint32_t size)
{
  int nwfile=-1;

  if(!tofile || !buffer)
    crash_burn("arguments");

  if(lseek(file,offset,SEEK_SET) == -1)
    goto badend;

  if(read(file,buffer,size) == -1)
    goto badend;

  if((nwfile=open(tofile,O_CREAT|O_TRUNC|O_WRONLY,0644)) == -1)
    goto badend;

  if(write(nwfile,buffer,size) == -1)
    goto badend;

  close(nwfile);

  return 1;

 badend:

  if(nwfile != -1)
    close(nwfile);

  return 0;
}

static char *str_path_dup(char *path, char *file)
{
  unsigned int pathlen;
  char *ret;

  pathlen=strlen(path);

  ret=malloc(pathlen+1+strlen(file)+1);
  memcpy(ret,path,pathlen);
  ret[pathlen]=OS_DIR_SEPARATOR;
  strcpy(ret+pathlen+1,file);
  
  return ret;
}

typedef struct name_list
{
  char *name;
  uint32_t length;

  struct name_list *next,*prev;
} name_list ;

static name_list *name_list_append(name_list *list,char *name,uint32_t length)
{
  name_list *ret=malloc(sizeof(name_list));

  ret->name=name;
  ret->length=length;

  ret->prev=list;
  ret->next=NULL;

  if(list)
    list->next=ret;

  return ret;
}

name_list *name_list_add(name_list *list,char *name)
{
  return name_list_append(list,name,0);
}

static name_list *name_list_rewind(name_list *list)
{
  name_list *ret;

  for(ret=list;ret && ret->prev;ret=ret->prev)
    ;

  return ret;
}

static void name_list_free_internal(name_list *list, int free_payload)
{
  name_list *beta,*gamma;

  beta=name_list_rewind(list);

  for(;beta!=NULL;)
  {
    gamma=beta->next;

    if(free_payload)
      nullify(beta->name);

    nullify(beta);
    beta=gamma;
  }
}

void name_list_free(name_list *list)
{
  name_list_free_internal(list,TRUE);
}

/* some sanity checks for the read files */
static int tgw_sanity_check(uint32_t size,tgw_file *file)
{
  if(file->header.file_name_dir_offset != 116 ||
     file->header.file_name_dir_count != file->header.file_len_dir_count ||
     file->header.first_file_data_offset+file->header.file_headers_length 
       > size)
    return 0;
    
  return 1;
}

tgw_file *tgw_file_read_headers(char *path)
{
  tgw_file *ret=NULL;
  struct stat st;
  int file=-1;
  ssize_t count;

  if(!path)
    crash_burn("!path");

  if(stat(path,&st) == -1)
    goto badend;

  if(!S_ISREG(st.st_mode) || st.st_size < 116)
    crash_burn("file %s is not valid TGW-file",path);

  if((file=open(path,O_RDONLY)) == -1)
    goto badend;

  if(!(ret=malloc(sizeof(tgw_file))))
    goto badend;

  /* read the main header */
  if((count=read(file,&ret->header,sizeof(tgw_header)))== -1)
    goto badend;

  if(tgw_sanity_check(st.st_size,ret) == 0)
    crash_burn("file %s is not valid tgw",path);    

  /* allocate the fileheaders */
  ret->fnhdrs=malloc(
    sizeof(tgw_file_name_header)*ret->header.file_name_dir_count);
  ret->flhdrs=malloc(
    sizeof(tgw_file_length_header)*ret->header.file_name_dir_count);
  ret->fohdrs=malloc(
    sizeof(tgw_file_offset_header)*ret->header.file_name_dir_count);

  {
    #define HEADCOUNT 3
    
    uint32_t offsets[HEADCOUNT]={
      ret->header.file_name_dir_offset,
      ret->header.file_len_dir_offset,
      ret->header.file_off_dir_offset
    };
    void *hdrs[HEADCOUNT]={
      ret->fnhdrs,
      ret->flhdrs,
      ret->fohdrs,
    };
    
    size_t lengths[HEADCOUNT]={
      sizeof(tgw_file_name_header),
      sizeof(tgw_file_length_header),
      sizeof(tgw_file_offset_header)
    };

    unsigned int beta,gamma;

    for(gamma=0;gamma<HEADCOUNT;gamma++)
    {
      lseek(file,offsets[gamma],SEEK_SET);
      for(beta=0;beta<ret->header.file_name_dir_count;beta++)
        if(read(file,hdrs[gamma]+lengths[gamma]*beta,lengths[gamma]) == -1)
          goto badend;
    }

    #undef HEADCOUNT
  }

  ret->file=file;

  return ret;

 badend: 

  if(file != -1)
    close(file);

  print_err("Error with file \"%s\": %s\n",path,strerror(errno));

  nullify(ret);
  return NULL;
}

void tgw_file_free(tgw_file *archive)
{
  if(!archive)
    return;

  close(archive->file);
  nullify(archive->fnhdrs);
  nullify(archive->flhdrs);
  nullify(archive->fohdrs);
  nullify(archive);
}

int tgw_file_list(tgw_file *archive, uint8_t verbose)
{
  if(!archive)
    return 0;

  for(unsigned int beta=0;beta<archive->header.file_name_dir_count;beta++)
  {
    print_out("%s",archive->fnhdrs[beta].file_name);
    if(verbose)
      print_out(" %d\n",archive->fnhdrs[beta].file_length);
    else
      print_out("\n");
  }

  if(verbose)
  {
    print_out("%d files.\n",archive->header.file_name_dir_count);
  }

  return 1;
}


int tgw_file_extract(tgw_file *archive, name_list *names, char *basepath)
{
  uint32_t filebuflen=0;
  uint8_t *filebuf=NULL;
  char **namelist;
  char fname[FILE_NAME_MAX_LENGTH+1];
  unsigned int count=0;

  int cmpstr(const void *p1,const void *p2)
    { return strcmp(* (char * const *) p1, * (char * const *) p2); }

  if(!archive)
    return 0;

  if(!basepath)
    basepath=".";
    
  if(names == NULL)
  {
    count=archive->header.file_name_dir_count;

    namelist=malloc(sizeof(char*)*count);
    for(unsigned int beta=0;beta<count;beta++)
    {
      namelist[beta]=(char *)archive->fnhdrs[beta].file_name;
      if(filebuflen < archive->fnhdrs[beta].file_length)
        filebuflen=archive->fnhdrs[beta].file_length;
    }
  }
  else
  {
    uint32_t gamma;
    uint32_t nlen;
    name_list *real_list=NULL;

    names=name_list_rewind(names);
    
    /* count the number of files to be extracted.
       also check that the filenames are found inside the archive. */
    for(name_list *beta=names;beta!=NULL;beta=beta->next)
    {
      nlen=strlen(beta->name);

      for(gamma=0;gamma<archive->header.file_name_dir_count;gamma++)
        if(nlen == strlen((char *)archive->fnhdrs[gamma].file_name) &&
          strcmp((char *)archive->fnhdrs[gamma].file_name,beta->name) == 0)
        {
          real_list=name_list_add(real_list,beta->name);
          count++;

          if(filebuflen < archive->fnhdrs[gamma].file_length)
            filebuflen=archive->fnhdrs[gamma].file_length;

          break;
        }
      
      if(gamma == archive->header.file_name_dir_count)
        print_err("Warning: file \"%s\" not found in archive.\n",beta->name);

    }

    if(real_list == NULL)
    {
      print_err("Error: No files to extract.\n");
      return 0;
    }

    real_list=name_list_rewind(real_list);

    /* construct the proper namelist */
    namelist=malloc(sizeof(char*)*count);
    gamma=0;
    for(name_list *beta=real_list;
        beta!=NULL;
        beta=beta->next,gamma++)
      namelist[gamma]=beta->name;
    
    name_list_free_internal(real_list,FALSE);
  }

  qsort(namelist,count,sizeof(char*),cmpstr);

  /* create the directories */
  {
    char dir[FILE_NAME_MAX_LENGTH+1];
    int prevpos=-2,pos=0;

    for(unsigned int beta=0;
        beta<count;
        beta++,
        prevpos=pos)
    {
      pos=strlen(namelist[beta])-1;

      for(;pos > 0; pos--)
        if(namelist[beta][pos] == FILE_NAME_DIR_SEPARATOR)
          break;

      /* skip the duplicates */
      if(pos == prevpos && strncmp(namelist[beta],dir,pos) == 0)
        continue;

      memcpy(dir,namelist[beta],pos);
      dir[pos]=0;

      for(unsigned int gamma=0;dir[gamma] != 0;gamma++)
        if(dir[gamma]==FILE_NAME_DIR_SEPARATOR)
          dir[gamma]=OS_DIR_SEPARATOR;

      if(mkdir_p(basepath,dir) == 0)
        goto badend;
    }
  }

  /* extract the files */
  {
    char sep[]={OS_DIR_SEPARATOR,0};
    filebuf=malloc(sizeof(uint8_t)*(filebuflen+1));


    for(unsigned int beta=0,gamma=0,nlen=0;beta<count;beta++)
    {
      strcpy(fname,basepath);
      memmove(fname+strlen(fname),sep,sizeof(sep));
      strcat(fname,namelist[beta]);

      for(unsigned int gamma=0;fname[gamma] != 0;gamma++)
        if(fname[gamma]==FILE_NAME_DIR_SEPARATOR)
          fname[gamma]=OS_DIR_SEPARATOR;
      
      if(verbose)
        print_out("%s\n",fname);

      nlen=strlen(namelist[beta]);

      /* search and extract the right file */
      for(gamma=0;gamma<archive->header.file_name_dir_count;gamma++)
        if(nlen == strlen((char *)archive->fnhdrs[gamma].file_name) &&
          strcmp(namelist[beta],(char *)archive->fnhdrs[gamma].file_name) == 0)
        {
          if(extract_file(archive->file,fname,filebuf,
               archive->fohdrs[gamma].file_offset,
               archive->fnhdrs[gamma].file_length) == 0)
            goto badend;          
        }
    }

    nullify(namelist);
    nullify(filebuf);
  }

  return 1;

 badend: ;
  print_err("Error extracting archive");
  
  if(filebuf)
    print_err(" while processing \"%s\":",fname);

  if(errno)
    print_err(" %s",strerror(errno));

  print_err(".\n");

  nullify(namelist);
  nullify(filebuf);

  return 0;
}

static name_list *append_dir(char *path,name_list *files)
{
  DIR *dir;
  char *tmp;
  struct dirent *dent;
  struct stat st;

  dir=opendir(path);

  while((dent=readdir(dir)) != NULL)
  {
    tmp=str_path_dup(path,dent->d_name);

    stat(tmp,&st);
    
    if(S_ISDIR(st.st_mode))
    {
      if(strcmp(dent->d_name,".") != 0 &&
        strcmp(dent->d_name,"..") != 0)
        files=append_dir(tmp,files);

      nullify(tmp);
      continue;
    }    

    /* if it is a file */
    files=name_list_append(files,tmp,(uint32_t)st.st_size);
  }

  closedir(dir);

  return files;
}

static name_list *append_files(name_list *files)
{
  name_list *ret=NULL;
  struct stat st;

  if(!files)
    return NULL;

  files=name_list_rewind(files);

  for(name_list *beta=files; beta!=NULL; beta=beta->next)
  {
    if(stat(beta->name,&st) == -1)
      goto badend;

    if(S_ISDIR(st.st_mode))
      ret=append_dir(beta->name,ret);
    else
      ret=name_list_append(ret,strdup(beta->name),(uint32_t)st.st_size);    
  }

  return name_list_rewind(ret);

 badend:
  if(errno)
    perror(THIS_FUNCTION);

  name_list_free(ret);

  return NULL;
}


static char *file_to_buf(char *path,char *buf,uint32_t length)
{
  int file;
  char *ret=buf;

  if(!ret)
    ret=malloc(length);

  if((file=open(path,O_RDONLY)) == -1)
    goto badend;

  if(read(file,ret,length) == -1)
    goto badend;

  close(file);

  return ret;

 badend:
  if(errno)
    perror(THIS_FUNCTION);

  nullify(ret);

  return NULL;
}

static const uint32_t tgw_header_start[] = {
  0x00010006,30000000,1000,20,1000000,2,2,44100,176400
};

static const char *header_len_suffices[] = {"INI","TGM","WAV"};
static const unsigned int header_len_skips[] = {0,0,36};
static const unsigned int header_len_count=3;

#define uint32_swap(u)                          \
 (((u&0xFF)<<24)|((u&0xFF00)<<8)|               \
  ((u&0xFF0000)>>8)|((u&0xFF000000)>>24))

static unsigned int get_file_header_length(char *path,uint32_t length)
{
  unsigned int ret=0,len;

  /* check for the constant header lengths */
  len=strlen(path);
  for(unsigned int beta=0;beta<header_len_count;beta++)
    if(strncmp(header_len_suffices[beta],path+len-3,3) == 0)
      return header_len_skips[beta];

  /* TGR has a variable header length */
  if(length > 0x13 && strncmp("TGR",path+len-3,3) == 0)
  {
    char *buf;

    buf=file_to_buf(path,NULL,0x14);

    memcpy(&ret,buf+0x10,sizeof(uint32_t));

    nullify(buf);

    /* for some reason the header length is bigendian */
    ret=uint32_swap(ret);
    ret+=20;
  }

  return ret;
}

static uint32_t increase2next(uint32_t orig,uint32_t multiplier)
{
  uint32_t beta;

  for(beta=1;beta*multiplier<orig;beta++)
    ;

  return beta*multiplier;
}

static uint32_t tgw_hash(char *name)
{
  char *a=name;
  uint32_t b=0;

  if(name)
    for(b=*(a++)<<8;*a!=0;a++)
      b+=(b>>4)**a+(a-name-1);

  return b;
}

/* strip multiple separators and separators from the end of the string */
static char *correct_separators(char *str,uint8_t separator)
{
  unsigned int beta,len;

  if(!str)
    return NULL;

  len=strlen(str);

  for(beta=0;beta<len;beta++)
  {
    if(str[beta] == separator && 
      (str[beta+1] == 0 || str[beta+1] == separator))
    {
      memmove(str+beta,str+beta+1,len-beta);

      beta--;
      len--;
    }
  }
  return str;
}

/* bail if write fails */
#define WRITE_CHECK(fd,data,length)    \
  do{ if(write((fd),(data),(length)) == -1) goto badend; } while(0)

int tgw_file_create(int archive, name_list *files)
{
  tgw_header hdr;
  tgw_file_name_header *fnhdrs;
  tgw_file_length_header *flhdrs;
  tgw_file_offset_header *fohdrs;

  name_list *names;
  uint32_t filecount=0,gamma,namelen,offset;
  uint32_t headeroffset=0;
  uint32_t lfilelen=0;

  /* prepare the files */
  names=append_files(files);

  for(name_list *beta=names;beta!=NULL;beta=beta->next)
  {
    filecount++;
    if(beta->length > lfilelen)
      lfilelen=beta->length;
  }

  /* init the header */
  memset(&hdr,0,sizeof(tgw_header));
  memcpy(&hdr,tgw_header_start,sizeof(tgw_header_start));

  hdr.file_name_dir_count=
    hdr.file_len_dir_count=
    hdr.file_off_dir_count=filecount;

  hdr.fdo1=
    hdr.fdo2=
    hdr.file_name_dir_offset=sizeof(tgw_header);

  hdr.file_len_dir_offset=hdr.file_name_dir_offset+
    sizeof(tgw_file_name_header)*filecount;

  hdr.file_off_dir_offset=hdr.file_len_dir_offset+
    sizeof(tgw_file_length_header)*filecount;

  hdr.first_file_data_offset=hdr.file_off_dir_offset+
    sizeof(tgw_file_offset_header)*filecount;

#ifdef DEBUG
  print_out("fc %d, fndo %d, fldo %d, fodo %d, ffdo %d\n",
    filecount,
    hdr.file_name_dir_offset,
    hdr.file_len_dir_offset,
    hdr.file_off_dir_offset,
    hdr.first_file_data_offset);
#endif

  /* create the filecount dependent headers */
  fnhdrs=malloc(sizeof(tgw_file_name_header)*filecount);
  flhdrs=malloc(sizeof(tgw_file_length_header)*filecount);
  fohdrs=malloc(sizeof(tgw_file_offset_header)*filecount);

  /* fill the necessary data */
  offset=hdr.first_file_data_offset;
  gamma=0;
  for(name_list *beta=names;beta!=NULL;beta=beta->next,gamma++)
  {
    namelen=(strlen(beta->name) < FILE_NAME_MAX_LENGTH-1) ? 
      strlen(beta->name) : FILE_NAME_MAX_LENGTH-1;

    memcpy(fnhdrs[gamma].file_name,beta->name,namelen);
    memset(&fnhdrs[gamma].file_name[namelen],0,FILE_NAME_MAX_LENGTH-namelen);

    /* correct the separators */
    for(unsigned int delta=0;delta<namelen;delta++)
      if(fnhdrs[gamma].file_name[delta]==OS_DIR_SEPARATOR)
        fnhdrs[gamma].file_name[delta]=FILE_NAME_DIR_SEPARATOR;

    correct_separators((char *)fnhdrs[gamma].file_name,
      FILE_NAME_DIR_SEPARATOR);

    fnhdrs[gamma].name_hash=tgw_hash((char *)fnhdrs[gamma].file_name);
    fnhdrs[gamma].file_length=beta->length;
    fnhdrs[gamma].unknown2=1;
    fnhdrs[gamma].file_ID=gamma;

    memset(flhdrs[gamma].null,0,sizeof(flhdrs[gamma].null));
    flhdrs[gamma].file_length=beta->length;
    flhdrs[gamma].unknown=1;
    flhdrs[gamma].file_ID=gamma;

    /* read the fileheader sizes into the filenameheader */
    fnhdrs[gamma].file_header_length=
      get_file_header_length(beta->name,beta->length);

    if(fnhdrs[gamma].file_header_length != 0)
    {
      fnhdrs[gamma].file_header_offset=headeroffset;
      headeroffset+=fnhdrs[gamma].file_header_length;
    }
    else
      fnhdrs[gamma].file_header_offset=0;
  }

  hdr.file_headers_length=headeroffset+fnhdrs[gamma].file_header_length;
  
  /* write the fileoffsets */
  offset=increase2next(hdr.first_file_data_offset+hdr.file_headers_length,
    FILE_SLOT_LENGTH);
  gamma=0;
  for(name_list *beta=names;beta!=NULL;beta=beta->next,gamma++)
  {
    fohdrs[gamma].file_offset=offset;
    fohdrs[gamma].file_end_offset=offset+beta->length;    
    offset+=increase2next(beta->length,FILE_SLOT_LENGTH);
  }

  /* begin writing the file */
  {
    char *buf;
    char byte;

    if(verbose)
      print_out("Writing headers ..\n");

    /* write the headers */
    WRITE_CHECK(archive,&hdr,sizeof(tgw_header));
    WRITE_CHECK(archive,fnhdrs,sizeof(tgw_file_name_header)*filecount);
    WRITE_CHECK(archive,flhdrs,sizeof(tgw_file_length_header)*filecount);
    WRITE_CHECK(archive,fohdrs,sizeof(tgw_file_offset_header)*filecount);

    if(verbose)
      print_out("Writing files ..\n");

    /* allocate the buffer for file data */
    buf=malloc(lfilelen);

    /* write the files */
    gamma=0;
    for(name_list *beta=names;beta!=NULL;beta=beta->next,gamma++)
    {
      file_to_buf(beta->name,buf,beta->length);

      /* write the possible header */
      if(fnhdrs[gamma].file_header_length > 0)
      {
        lseek(archive,hdr.first_file_data_offset+
          fnhdrs[gamma].file_header_offset,SEEK_SET);
        WRITE_CHECK(archive,buf,fnhdrs[gamma].file_header_length);
      }

      /* write the data */
      lseek(archive,fohdrs[gamma].file_offset,SEEK_SET);
      WRITE_CHECK(archive,buf,beta->length);

      if(verbose)
        print_out("%s\n",beta->name);
    }

    nullify(buf);

    if(verbose)
      print_out("%d files added.\n",gamma);

    /* write zeroes to the end of the file, so that the last file's length
       is divisible by 2048 */
    gamma--;
    byte=0;
    lseek(archive,fohdrs[gamma].file_offset+
      increase2next(flhdrs[gamma].file_length,FILE_SLOT_LENGTH)-1,SEEK_SET);
    WRITE_CHECK(archive,&byte,1);
  }

  nullify(fnhdrs);
  nullify(flhdrs);
  nullify(fohdrs);
  name_list_free(names);

  return 1;

 badend: ;
  print_err("Error writing archive");

  if(errno)
    print_err(": %s",strerror(errno));

  print_err(".\n");

  nullify(fnhdrs);
  nullify(flhdrs);
  nullify(fohdrs);
  name_list_free(names);

  return 0;
}

#ifdef DEBUG
int tgw_file_print2(tgw_file *archive, uint8_t verbose)
{
  if(!archive)
    return 0;

  /*
  print_out("fnhd_unk1=[");
  for(unsigned int beta=0;beta<archive->header.file_name_dir_count;beta++)
    print_out("%u,",archive->fnhdrs[beta].name_hash);
  print_out("];\n");

  print_out("file_off_diffs=[");
  for(unsigned int beta=0;beta<archive->header.file_name_dir_count-1;beta++)
    print_out("%d,",archive->fohdrs[beta+1].file_offset-
      archive->fohdrs[beta].file_end_offset);
  print_out("];\n");
  */

  print_out("file_names=[");
  for(unsigned int beta=0;beta<archive->header.file_name_dir_count;beta++)
    print_out("  \"%s\",\n",archive->fnhdrs[beta].file_name);
  print_out("];\n");

  print_out("file_hashes=[");
  for(unsigned int beta=0;beta<archive->header.file_name_dir_count;beta++)
    print_out("%u,",archive->fnhdrs[beta].name_hash);
  print_out("];\n");

  return 0;
}

int tgw_file_print(tgw_file *archive, uint8_t verbose)
{
  unsigned int gamma;

  if(!archive)
    return 0;

  for(unsigned int beta=0;beta<archive->header.file_name_dir_count;beta++)
  {
    print_out("%s",archive->fnhdrs[beta].file_name);
    if(verbose)
      print_out(" %d\n",archive->fnhdrs[beta].file_length);
    else
      print_out("\n");
    print_out("  fnameheader: name_hash %u file_length %d "
      "unknown2 %d id %d fh_off %d fh_len %d\n",
      archive->fnhdrs[beta].name_hash,archive->fnhdrs[beta].file_length,
      archive->fnhdrs[beta].unknown2,archive->fnhdrs[beta].file_ID, 
      archive->fnhdrs[beta].file_header_offset,
      archive->fnhdrs[beta].file_header_length);

    print_out("  flenheader: null:");
    for(gamma=0;gamma<2;gamma++)
      print_out("[%d] ",archive->flhdrs[beta].null[gamma]);
    print_out(" file_len %d unknown %d file_id %d\n",
      archive->flhdrs[beta].file_length,archive->flhdrs[beta].unknown,
      archive->flhdrs[beta].file_ID);

    print_out("  foffsetheader: offset %d end_offset %d\n",
      archive->fohdrs[beta].file_offset,
      archive->fohdrs[beta].file_end_offset);
  }

  if(verbose)
  {
    print_out("%d files.\n",archive->header.file_name_dir_count);

    print_out("magic 0x%.8X\nunknown2: ",archive->header.magic);
    for(gamma=0;gamma<8;gamma++)
      print_out("[%4d] ",archive->header.unknown2[gamma]);
    print_out("\n");

    print_out("fdo1: %d\n",archive->header.fdo1);
    print_out("null1: ");
    for(gamma=0;gamma<3;gamma++)
      print_out("[%d] ",archive->header.null1[gamma]);
    print_out("\n");

    print_out("fdo2: %d\nnull2 %d\n",archive->header.fdo2,
      archive->header.null2);

    print_out("fndo %d\tfndc %d\n",
      archive->header.file_name_dir_offset,
      archive->header.file_name_dir_count);
    print_out("fldo %d\tfldc %d\n",
      archive->header.file_len_dir_offset,
      archive->header.file_len_dir_count);
    print_out("fodo %d\tfodc %d\n",
      archive->header.file_off_dir_offset,
      archive->header.file_off_dir_count);

    print_out("null3: ");
    for(gamma=0;gamma<3;gamma++)
      print_out("[%d] ",archive->header.null3[gamma]);
    print_out("\n");

    print_out("ffdo %d\nfile_headers_length %d\n",
      archive->header.first_file_data_offset,
      archive->header.file_headers_length);

    print_out("null4: ");
    for(gamma=0;gamma<3;gamma++)
      print_out("[%d] ",archive->header.null4[gamma]);
    print_out("\n");
  }
  return 1;
}
#endif
