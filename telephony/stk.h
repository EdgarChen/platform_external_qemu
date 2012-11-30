/* Copyright (C) 2012 Mozilla Foundation and Mozilla contributors
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#ifndef _STK_H
#define _STK_H

#include "gsm.h"
#include "sysdeps.h"
#include "sim_card.h"
#include <stdint.h>

//#define STK_PDU_DISPLAY_TEXT_OK "D00E8103012100820281028D03044F4B"
//#define STK_PDU_DISPLAY_TEXT_ERROR "D0118103012100820281028D06044552524F52"
//more time D009810301020082028182


#define STK_TLV_TAG_PROACTIVE_COMMAND 0xD0

#define STK_TLV_TAG_COMMAND_DETAILS   0x01

typedef enum {
    A_STK_PROACTIVE_PROVIDE_LOCAL_INFO = 0,
} AStkProactiveType;

#define MAX_BUFFER_SIZE 128
typedef struct AStkProactiveCmdRec {
    AStkProactiveType type;
    char              pdu[MAX_BUFFER_SIZE];
} AStkProactiveCmdRec, *AStkProactiveCmd;

typedef struct AStkRec_* AStk;

extern AStk astk_create( int port, int instance_id );
extern void astk_destroy( AStk stk );

// for proactive command
extern void astk_process_proactive_command( AStk stk, const char* cmdPdu );
extern int astk_get_proactive_command_count( AStk stk );
extern AStkProactiveCmd astk_get_proactive_command( AStk stk, int index );

// for other stk command
extern void astk_process_command( AStk  stk, const char* cmdPdu );

#endif /* _STK_H  */
