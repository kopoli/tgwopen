/***************************************************************************
  Name:         llist.c
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

#include "commonconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "llist.h"

#define LLIST_ERROR_REPORT(LLIST_ERROR) \
  fputs(LLIST_ERROR, stderr);


/***************************************************************************
  Types
 ***************************************************************************/

/***************************************************************************
  Externals
 ***************************************************************************/

/* Should the IL_ReportError be used to report failures. */
tvalue linked_list_use_error = TRUE;

/***************************************************************************
  Internals
 ***************************************************************************/

/***************************************************************************
  Functions
 ***************************************************************************/

/*
  Just for the record. This linked list implementation works by having a 
  default cell always. Also there is an empty cell in the end of the list.
  It is always the list->Last->Next.
 */

static const char *IL_LLISTCREATE_ERROR =
 "Error: Could not initialize linked list.\n";

linked_list *linked_list_create()
{
  linked_list *list;

  list = (linked_list *) malloc(sizeof(linked_list));
  if(list == NULL)
  {
    LLIST_ERROR_REPORT(IL_LLISTCREATE_ERROR);
    return NULL;
  }

  /* Create the default cell */
  list->First = (linked_list_cell *) malloc(sizeof(linked_list_cell));
  if(list->First == NULL)
  {
    LLIST_ERROR_REPORT(IL_LLISTCREATE_ERROR);
    return NULL;
  }

  /* set the addresses */
  list->Last = list->First;
  list->First->Data = NULL;
  list->First->Next = list->First;

  return list;
}

/* Deletes a list. Only deletes the list and leaves the data alone. */
tvalue linked_list_delete(linked_list * list)
{
  linked_list_cell *This, *next = NULL;

  ARG_ASSERT(!list, FALSE);

  This = list->First;

  /* If something else has been allocated than the default one */
  if(list->Last != list->Last->Next)
    while(This->Next != NULL)
    {
      next = This->Next;
      nullify(This);
      This = next;
    }

  nullify(This);

  /* Delete the list */
  nullify(list);

  return TRUE;
}

static const char *IL_LLISTDATAADD_ERROR =
 "Error: Could not add an item to the linked list.\n";

/* Adds an item into the list. */
tvalue linked_list_add_data(linked_list * list, void *Data)
{
  linked_list_cell *This;

  /* The data can be NULL */
  ARG_ASSERT(!list, FALSE);

  This = list->Last->Next;

  This->Next = (linked_list_cell *) malloc(sizeof(linked_list_cell));
  if(This->Next == NULL)
  {
    LLIST_ERROR_REPORT(IL_LLISTDATAADD_ERROR);
    return FALSE;
  }

  /* Make this new one invalid */
  This->Next->Next = NULL;
  This->Next->Data = NULL;

  /* Set the data */
  This->Data = Data;
  list->Last = This;

  return TRUE;
}

/* adds an item into the front of the list */
tvalue linked_list_add_front(linked_list * list, void *Data)
{
  linked_list_cell *This, *newlast;

  ARG_ASSERT(!list || !Data, FALSE);

  This = list->Last->Next;

  /* Set up a new last item. */
  newlast = (linked_list_cell *) malloc(sizeof(linked_list_cell));
  if(newlast == NULL)
  {
    LLIST_ERROR_REPORT(IL_LLISTDATAADD_ERROR);
    return FALSE;
  }

  newlast->Next = NULL;
  newlast->Data = NULL;
  list->Last->Next = newlast;

  /* Put the new item as the first */
  This->Data = Data;

  /* if this is the first allocation */
  if(This == list->First)
    list->Last = list->First;
  else
    This->Next = list->First;

  list->First = This;
  return TRUE;
}

/* adds an item into the wanted position in the list */
tvalue linked_list_add_pos(linked_list * list, void *Data, unsigned int pos)
{
	register unsigned int beta;
  register linked_list_cell *This, *prev;
	linked_list_cell *newitem;

  ARG_ASSERT(!list || !Data, FALSE);

  This = list->First;
  prev = NULL;

	for(beta=0;beta<pos;beta++)
	{
    /* Shuffled through the list and there was no such index */
    if(This == list->Last && beta != pos - 1)
      return FALSE;

    prev = This;
    This = This->Next;
	}

  newitem = (linked_list_cell *) malloc(sizeof(linked_list_cell));
  if(newitem == NULL)
  {
    LLIST_ERROR_REPORT(IL_LLISTDATAADD_ERROR);
    return FALSE;
  }

	/* set the hooks */
	prev->Next=newitem;
	newitem->Next=This;

	newitem->Data=Data;

	return TRUE;
}


static void deletefrompos(linked_list * list, linked_list_cell * This,
 linked_list_cell * prev)
{
  /* Mend the connections */
  if(This == list->First)
  {
    /* If there is only one cell in the list */
    if(This == list->Last)
    {
      /* Delete the empty-one from the end */
      nullify(list->Last->Next);

      /* Set up the starting environment */
      list->Last = list->First;
      list->First->Data = NULL;
      list->First->Next = list->First;
      return;
    }
    else
      list->First = This->Next;
  }
  /* If the cell is the last one */
  else if(This == list->Last)
  {
    prev->Next = list->Last->Next;
    list->Last = prev;
  }
  else
    prev->Next = This->Next;

  nullify(This);
}


tvalue linked_list_delete_data(linked_list * list, void *Data)
{
  linked_list_cell *This, *prev;

  /* The data can be NULL. Only the first NULL will be deleted. */
  ARG_ASSERT(!list, FALSE); 
  This = list->First;
  prev = NULL;

  while(This->Data != Data && This != list->Last)
  {
    prev = This;
    This = This->Next;
  }

  /* If not found */
  if(This->Data != Data && This == list->Last)
    return FALSE;

  deletefrompos(list, This, prev);

  return TRUE;
}

tvalue linked_list_delete_pos(linked_list * list, unsigned int uiIndex)
{
  register linked_list_cell *This, *prev;
  register unsigned int beta;

  ARG_ASSERT(!list, FALSE);

  This = list->First;
  prev = NULL;

  for(beta = 0; beta < uiIndex; beta++)
  {
    /* Shuffled through the list and there was no such index */
    if(This == list->Last && beta != uiIndex - 1)
      return FALSE;

    prev = This;
    This = This->Next;
  }

  deletefrompos(list, This, prev);

  return TRUE;
}

void *linked_list_get_pos(linked_list * list, unsigned int uiIndex)
{
  linked_list_cell *This = NULL;
  register unsigned int beta;

  ARG_ASSERT(!list, NULL);

  if(uiIndex == 0)
    return list->First->Data;

  This = list->First;

  for(beta = 0; beta < uiIndex; beta++)
  {
    /* Shuffled through the list and there was no such index */
    if(This == list->Last && beta != uiIndex - 1)
      return NULL;

    This = This->Next;
  }

  return This->Data;
}

/* 
  Cycles through the list.
  returns the first element if pos == NULL
  returns pos->Next if pos != NULL
  returns NULL if pos == list->Last
 */

linked_list_cell *linked_list_cycle(linked_list * list, linked_list_cell *pos)
{
  ARG_ASSERT(!list, NULL);

  if(pos == NULL)
    return list->First;

  if(pos != list->Last)
    return pos->Next;

  return NULL;
}


//#define IL_LLIST_DEBUG 
#ifdef IL_LLIST_DEBUG

int main()
{
  linked_list_cell *pos;
  linked_list *lista;
  char *ptr = NULL;
  char *hauki = "hauki!!!";
  register unsigned int beta = 0;

  lista = linked_list_create();

  linked_list_add_data(lista, hauki);
  linked_list_add_data(lista, "kissa");
  linked_list_add_data(lista, "haukka");


  // An example shuffling through the values of the list
  while((pos = linked_list_cycle(lista, pos)) != NULL)
  {
    printf("%d. %s\n", beta, pos->Data);
    beta++;
  }

  // get "precise" data
  printf("yksitellen: %s\n", (char *) linked_list_get_pos(lista, 0));
  printf("yksitellen: %s\n", (char *) linked_list_get_pos(lista, 2));
  printf("yksitellen: %s\n", (char *) linked_list_get_pos(lista, 1));

  linked_list_delete_data(lista, hauki);
  linked_list_add_data(lista, hauki);

  linked_list_add_pos(lista, "lehmä",2);

  beta = 0;
  while(1)
  {
    ptr = linked_list_cycle(lista, ptr);

    if(ptr == NULL)
      break;

    printf("%d. %s\n", beta, ptr);
    beta++;
  }

  linked_list_delete(lista);

  return 0;
}

#endif
