/***************************************************************************
  Name:         llist.h
  Description:  A low level linked list implementation
  Created:      Tue Nov 25 23:44:37 EET 2003
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

#ifndef IL_LLIST_HEADER
#define IL_LLIST_HEADER

#include <common/defines.h>

/****************************************************************************
  Defines / Structures / data types
 ****************************************************************************/

/* A cell of the linked list */
typedef struct linked_list_cell
{
  void *Data;
  struct linked_list_cell *Next;

} linked_list_cell;

typedef struct linked_list
{
  linked_list_cell *First;          /* The first cell */
  linked_list_cell *Last;           /* The last cell */

} linked_list;

/* Should the IL_ReportError be used to report failures. */
extern tvalue linked_list_use_error;

/****************************************************************************
  Prototypes
 ****************************************************************************/

/* Create the list */
linked_list *linked_list_create();

/* Delete the list */
tvalue linked_list_delete(linked_list * list);

/* Add data in the end of the list */
tvalue linked_list_add_data(linked_list * list, void *Data);

/* Add data in the front of the list */
tvalue linked_list_add_front(linked_list * list, void *Data);

/* Add data in the wanted position in the list */
tvalue linked_list_add_pos(linked_list * list, void *Data, unsigned int pos);

/* Delete cells by data */
tvalue linked_list_delete_data(linked_list * list, void *Data);

/* Delete cell by index */
tvalue linked_list_delete_pos(linked_list * list, unsigned int uiIndex);

/* Get the data by index */
void *linked_list_get_pos(linked_list * list, unsigned int uiIndex);

/* Cycle through the list */
linked_list_cell *linked_list_cycle(linked_list * list, linked_list_cell *pos);

#endif
