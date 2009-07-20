/*
  TGW-file handling functions.

  tgw.c and tgw.h, 2007, public domain.
*/
#ifndef FORMAT_HEADER
#define FORMAT_HEADER

#include <stdint.h>

#define FILE_NAME_MAX_LENGTH 80
#define FILE_NAME_DIR_SEPARATOR '\\'

#define OS_DIR_SEPARATOR '/'

#define FILE_SLOT_LENGTH 2048

typedef struct 
{
  uint32_t magic;       //0x00010006
  uint32_t unknown2[8]; //30000000,1000,20,1000000,2,2,44100,176400
  uint32_t fdo1;
  uint32_t null1[3];
  uint32_t fdo2;
  uint32_t null2;
  uint32_t file_name_dir_offset;
  uint32_t file_name_dir_count;
  uint32_t file_len_dir_offset;
  uint32_t file_len_dir_count;
  uint32_t file_off_dir_offset;
  uint32_t file_off_dir_count;
  uint32_t null3[3];
  uint32_t first_file_data_offset;
  uint32_t file_headers_length; 
  uint32_t null4[3];  
} tgw_header;

typedef struct
{
  uint8_t file_name[FILE_NAME_MAX_LENGTH];
  uint32_t name_hash;
  uint32_t file_length;
  uint32_t unknown2;     //1
  uint32_t file_ID;
  uint32_t file_header_offset;
  uint32_t file_header_length;
} tgw_file_name_header;

typedef struct
{
  uint32_t null[2];
  uint32_t file_length;
  uint32_t unknown;      //1
  uint32_t file_ID;
} tgw_file_length_header;

typedef struct
{
  uint32_t file_offset;
  uint32_t file_end_offset;
} tgw_file_offset_header;


typedef struct
{
  int file;

  tgw_header header;

  tgw_file_name_header *fnhdrs;
  tgw_file_length_header *flhdrs;
  tgw_file_offset_header *fohdrs;

} tgw_file;

#ifndef TGW_INTERNAL
typedef void name_list;

name_list *name_list_add(name_list *list,char *name);
void name_list_free(name_list *list);

tgw_file *tgw_file_read_headers(char *path);
void      tgw_file_free(tgw_file *archive);
int       tgw_file_list(tgw_file *archive, uint8_t verbose);
int       tgw_file_extract(tgw_file *archive, name_list *names, 
                           char *basepath);
int       tgw_file_create(int archive, name_list *files);

#endif /* TGW_INTERNAL */

#endif
