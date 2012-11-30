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
#include "stk.h"
#include "android/utils/debug.h"
#include "android/utils/misc.h"
#include "android/android.h"
#include "qemu-common.h"
#include "qemu-thread.h"
#include "sockets.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define  DEBUG  1

#if  1
#  define  D_ACTIVE  VERBOSE_CHECK(modem)
#else
#  define  D_ACTIVE  DEBUG
#endif

#if 1
#  define  R_ACTIVE  VERBOSE_CHECK(radio)
#else
#  define  R_ACTIVE  DEBUG
#endif

#if DEBUG
#  define  D(...)   do { if (D_ACTIVE) fprintf( stderr, __VA_ARGS__ ); } while (0)
#  define  R(...)   do { if (R_ACTIVE) fprintf( stderr, __VA_ARGS__ ); } while (0)
#else
#  define  D(...)   ((void)0)
#  define  R(...)   ((void)0)
#endif

// Command Detail Tlv
typedef struct AStkTlvCommandDetailsRec {
    uint8_t tag;
    uint8_t length;
    uint8_t number;
    uint8_t type;
    uint8_t qualifier;
} AStkTlvCommandDetailsRec, *AStkTlvCommandDetails;

// Other Tlv
typedef struct AStkTlvOtherRec {
    uint8_t  tag;
    uint32_t length;
    uint8_t  data[MAX_BUFFER_SIZE];
} AStkTlvOtherRec, *AStkTlvOther;

#define MAX_OTHER_TLV 10
typedef struct AStkTlvRec {
    AStkTlvCommandDetails commandDetails;
    AStkTlvOtherRec       others[MAX_OTHER_TLV];
    int                   othersCount;
} AStkTlvRec, *AStkTlv;

typedef struct AStkProactiveRec {
    AStkProactiveCmdRec command;
    AStkTlvRec          tlv;
} AStkProactiveRec, *AStkProactive;

#define MAX_PROACTIVES 10
typedef struct AStkRec_ {

    /* Proactive command */
    AStkProactiveRec proactives[MAX_PROACTIVES];
    int              proactivesCount;

    /* SysChannle */
    SysChannel       channel;
    QemuMutex        mutex;
    char             buff[MAX_BUFFER_SIZE];
    int              port;
    int              buff_len;
    int              buff_size;
    int              buff_pos;
} AStkRec;

static AStkRec _s_stk[MAX_GSM_DEVICES];

AStk
astk_create( int port, int instance_id )
{
    AStk stk = &_s_stk[instance_id];
    memset(stk, 0, sizeof(*stk));

    stk->port = port;

    qemu_mutex_init(&stk->mutex);

    stk->channel = sys_channel_create_tcp_client("localhost", port);
    stk->buff_size = (int) sizeof(stk->buff);

    return stk;
}

void
astk_destroy( AStk stk )
{
    qemu_mutex_destroy(&stk->mutex);

    /* nothing really */
    if (stk->channel)
        sys_channel_close(stk->channel);
}

static void
astk_tlv_free( AStkTlv tlv )
{
    if (tlv == NULL)
        return;

    if (tlv->commandDetails)
        free(tlv->commandDetails);

    memset(tlv, 0, sizeof(*tlv));
}

static AStkTlvOther
astk_other_tlv_alloc( AStkTlv tlv )
{
    AStkTlvOther other = NULL;
    int          count = tlv->othersCount;

    // ** [start] for Debug
    D("Edgar: astk_other_tlv_alloc: count = %d\n", count);
    // ** [end]

    if (count < MAX_OTHER_TLV) {
        other = tlv->others + count;

        tlv->othersCount += 1;
    }

    return other;
}

// SysChannel

static void
astk_channel_stop( AStk stk )
{
    sys_channel_on(stk->channel, 0, NULL, NULL);

    memset(stk->buff, 0, MAX_BUFFER_SIZE);
    stk->buff_pos = 0;
    stk->buff_size = 0;
}

static void
astk_event( void*  opaque, int  events )
{
    AStk stk = opaque;

    if (events & SYS_EVENT_WRITE) {
    }
}

// Parse Tlv

static int
astk_tlv_parser_int( const uint8_t** buffer, int len )
{
    if (buffer == NULL || *buffer == NULL || len < 0)
        return -1;

    if (strlen((char*)*buffer) < len)
        return -1;

    int ret = hex2int(*buffer, len);
    *buffer += len;

    return ret;
}

/**
 * | Byte                          |
 * | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
 * |CR | Tag Value                 |
 */
static int
astk_tlv_parser_comprehension_tag( const uint8_t** buffer, uint8_t* tag )
{
    if (tag == NULL)
        return -1;

    int len = 2;
    int result = astk_tlv_parser_int(buffer, len);
    if (result < 0)
        return -1;

    *tag = result & ~0x80;
    return len;
}

/**
 * Length   |  Byte 1  | Byte 2 | Byte 3 | Byte 4 |
 * 0 - 127  |  00 - 7f | N/A    | N/A    | N/A    |
 * 128-255  |  81      | 80 - ff| N/A    | N/A    |
 * 256-65535|  82      | 0100 - ffff     | N/A    |
 * 65536-   |  83      | 010000 - ffffff          |
 * 16777215
 */
static int
astk_tlv_parser_length( const uint8_t** buffer, uint32_t* length )
{
    if (length == NULL)
        return -1;

    int size = 2;
    int temp = astk_tlv_parser_int(buffer, size);

    if (temp < 0) {
        return -1;
    } else if (temp < 0x80) {
        *length = temp;
    } else if (temp == 0x81) {
        temp = astk_tlv_parser_int(buffer, 2);
        if (temp < 0x80)
            return -1;

        *length = temp;
        size += 2;
    } else if (temp == 0x82) {
        temp = astk_tlv_parser_int(buffer, 4);
        if (temp < 0x0100)
            return -1;

        *length = temp;
        size += 4;
    } else if (temp == 0x83) {
        temp = astk_tlv_parser_int(buffer, 6);
        if (temp < 0x010000)
            return -1;

        *length = temp;
        size += 6;
    } else {
        return -1;
    }

    return size;
}

static int
astk_tlv_parser_command_details( const uint8_t** buffer, AStkTlv tlv )
{
    int ret = 0;
    if (strlen((char*)*buffer) < 10)
        return -1;

    AStkTlvCommandDetails commandDetails = calloc( sizeof(*commandDetails), 1);

    ret = astk_tlv_parser_comprehension_tag(buffer, &commandDetails->tag);
    if (ret < 0 || commandDetails->tag != STK_TLV_TAG_COMMAND_DETAILS) {
        free(commandDetails);
        return -1;
    }

    commandDetails->length = astk_tlv_parser_int(buffer, 2);
    if (commandDetails->length != 3) {
        free(commandDetails);
        return -1;
    }

    commandDetails->number = astk_tlv_parser_int(buffer, 2);
    commandDetails->type = astk_tlv_parser_int(buffer, 2);
    commandDetails->qualifier = astk_tlv_parser_int(buffer, 2);

    tlv->commandDetails = commandDetails;
    return 10;
}

static int
astk_tlv_parser_other( const uint8_t** buffer, AStkTlv tlv )
{
    // ** [start] for Debug
    D("Edgar: astk_tlv_parser_other\n");
    // ** [end]
    AStkTlvOther other = astk_other_tlv_alloc(tlv);
    if (other == NULL)
        return -1;

    // ** [start] for Debug
    D("Edgar: astk_tlv_parser_other: alloc\n");
    // ** [end]

    int size = 0;
    int ret = astk_tlv_parser_comprehension_tag(buffer, &other->tag);
    if(ret < 0) return -1;
    size += ret;
    // ** [start] for Debug
    D("Edgar: astk_tlv_parser_other: ret = %d\n", ret);
    // ** [end]

    ret = astk_tlv_parser_length(buffer, &other->length);
    if(ret < 0) return -1;
    size += ret;
    // ** [start] for Debug
    D("Edgar: astk_tlv_parser_other: ret = %d\n", ret);
    D("Edgar: astk_tlv_parser_other: size = %d\n", size);
    D("Edgar: astk_tlv_parser_other: length = %d\n", other->length);
    // ** [end]

    if (strlen((char*)*buffer) < (other->length * 2))
        return -1;

    memcpy(other->data, *buffer, other->length * 2);
    *buffer += (other->length * 2);

    return (other->length * 2) + size;
}

typedef int (*TlvParser)(const uint8_t** buffer, AStkTlv tlv);

static const struct {
    const uint8_t   tag;
    const TlvParser parser;
} sDefaultTlvParser[] =
{
    /* command detail */
    {STK_TLV_TAG_COMMAND_DETAILS, astk_tlv_parser_command_details},

    /* end of list */
    {0xFF, NULL}
};

static int
astk_tlv_parser( const uint8_t** buffer, AStkTlv tlv )
{
    // ** [start] for Debug
    D("Edgar: astk_tlv_parser\n");
    // ** [end]
    int length = strlen((char*)*buffer);
    if ((length % 2) != 0) {
        return -1;
    }

    while (length > 0) {
        int i, found = 0, size =0;
        int tag = hex2int(*buffer, 2) & ~0x80;
        if (tag < 0)
            return -1;

        for (i= 0; ; i++) {
            const uint8_t temp = sDefaultTlvParser[i].tag;
            if (temp == 0xFF) {
                /* end of list*/
                break;
            }

            if (tag == temp) {
                found = 1;
                break;
            }
        }

        if (found) {
            TlvParser parser = sDefaultTlvParser[i].parser;
            size = parser(buffer, tlv);
        } else {
            // Use default parser
            size = astk_tlv_parser_other(buffer, tlv);
        }

        if (size < 0)
            return -1;

        // ** [start] for Debug
        D("Edgar: astk_tlv_parser: length = %d\n", length);
        D("Edgar: astk_tlv_parser: size = %d\n", size);
        // ** [end]
        length -= size;
    }

    return 0;
}

// STK Proactive Command

static AStkProactive
astk_proactive_command_alloc( AStk stk )
{
    AStkProactive proactive = NULL;
    int           count = stk->proactivesCount;

    if (count < MAX_PROACTIVES) {
        proactive = stk->proactives + count;

        stk->proactivesCount += 1;
    }
    return proactive;
}

static void
astk_proactive_command_free( AStk stk, AStkProactive proactive )
{
    int nn;

    // ** [start] for Debug
    AStkProactiveCmd command = &proactive->command;
    D("Edgar: remove proactive command: %s\n", command->pdu);
    // ** [end]

    AStkTlv tlv = &proactive->tlv;
    if (tlv)
      astk_tlv_free(tlv);

    for (nn = 0; nn < stk->proactivesCount; nn++) {
        if (stk->proactives + nn == proactive)
          break;
    }
    assert(nn < stk->proactivesCount);

    memmove(stk->proactives + nn,
            stk->proactives + nn +1,
            (stk->proactivesCount -1 - nn) * sizeof(*proactive));

    stk->proactivesCount -= 1;
}

static AStkProactive
astk_find_proactive_command( AStk stk, AStkTlv tlv )
{
    AStkProactive proactive = NULL;
    int count = stk->proactivesCount;
    int i, found = 0;

    for (i = 0; i < count; i++ ) {
        AStkTlv proactiveTlv = &stk->proactives[i].tlv;

        if (proactiveTlv->commandDetails &&
            tlv->commandDetails &&
            proactiveTlv->commandDetails->tag == tlv->commandDetails->tag &&
            proactiveTlv->commandDetails->length == tlv->commandDetails->length &&
            proactiveTlv->commandDetails->number == tlv->commandDetails->number &&
            proactiveTlv->commandDetails->type == tlv->commandDetails->type &&
            proactiveTlv->commandDetails->qualifier == tlv->commandDetails->qualifier
           ) {
            found = 1;
            break;
        }
    }

    if (found) {
        proactive = stk->proactives + i;
    }

    return proactive;
}

static int
astk_parse_proactive_command( const uint8_t** buffer, AStkProactive proactive )
{
    if (proactive == NULL ||
        (strlen((char*)*buffer) % 2) != 0)
        return -1;

    uint32_t length = 0;
    int size = 0;
    AStkProactiveCmd command = &proactive->command;

    // ** [start] for Debug
    D("Edgar: proactive command: %s\n", (char*)*buffer);
    D("Edgar: proactive length: %d\n", strlen((char*)*buffer));
    // ** [end]

    snprintf(command->pdu, MAX_BUFFER_SIZE, "%s", *buffer);

    if (astk_tlv_parser_int(buffer, 2) != STK_TLV_TAG_PROACTIVE_COMMAND)
        return -1;

    size = astk_tlv_parser_length(buffer, &length);
    if (size < 0)
        return -1;

    if (strlen((char*)*buffer) != (length * 2))
        return -1;

    AStkTlv tlv = &proactive->tlv;
    if (astk_tlv_parser(buffer, tlv) < 0)
        return -1;

    command->type = tlv->commandDetails->type;
    // ** [start] for Debug
    D("Edgar: proactive command: %s\n", command->pdu);
    D("Edgar: command\ttag = %d\n", tlv->commandDetails->tag);
    D("Edgar: command\tlength = %d\n", tlv->commandDetails->length);
    D("Edgar: command\tnumber = %d\n", tlv->commandDetails->number);
    D("Edgar: command\ttype = %d\n", tlv->commandDetails->type);
    D("Edgar: command\tqualifier = %d\n", tlv->commandDetails->qualifier);
    int nn;
    for (nn = 0; nn < tlv->othersCount; nn++) {
        D("Edgar: others[%d]\ttag = %d\n", nn, tlv->others[nn].tag);
        D("                 \tlength = %d\n", tlv->others[nn].length);
        D("                 \tdata = %s\n", tlv->others[nn].data);
    }
    // ** [end]
    return 0;
}

static int
astk_process_terminal_response( AStk stk, const char* command )
{
    // ** [start] for Debug
    D("Edgar: astk_process_terminal_response: %s\n", command);
    // ** [end]
    const uint8_t* buffer = (const uint8_t*) command;
    AStkTlvRec terminalResponse;
    memset(&terminalResponse, 0, sizeof(terminalResponse));

    if ( astk_tlv_parser(&buffer, &terminalResponse) < 0)
        return -1;

    // ** [start] for Debug
    D("Edgar: command\ttag = %d\n",       terminalResponse.commandDetails->tag);
    D("Edgar: command\tlength = %d\n",    terminalResponse.commandDetails->length);
    D("Edgar: command\tnumber = %d\n",    terminalResponse.commandDetails->number);
    D("Edgar: command\ttype = %d\n",      terminalResponse.commandDetails->type);
    D("Edgar: command\tqualifier = %d\n", terminalResponse.commandDetails->qualifier);
    int nn;
    for (nn = 0; nn < terminalResponse.othersCount; nn++) {
        D("Edgar: others[%d]\ttag = %d\n", nn, terminalResponse.others[nn].tag);
        D("                 \tlength = %d\n",  terminalResponse.others[nn].length);
        D("                 \tdata = %s\n",    terminalResponse.others[nn].data);
    }
    // ** [end]

    // TODO
    AStkProactive proactive = astk_find_proactive_command(stk, &terminalResponse);

    if (proactive) {
        // ** [start] for Debug
        D("Edgar: find proactive command: %s\n", proactive->command.pdu);
        // ** [end]

        astk_proactive_command_free(stk, proactive);
    }

    return 0;
}

// external function

int
astk_get_proactive_command_count( AStk stk )
{
    return stk->proactivesCount;
}

AStkProactiveCmd
astk_get_proactive_command( AStk stk, int index )
{
    if ((unsigned)index >= (unsigned)stk->proactivesCount)
        return NULL;

    return &stk->proactives[index].command;
}


void
astk_process_proactive_command( AStk stk, const char* cmdPdu )
{
    AStkProactive proactive = astk_proactive_command_alloc( stk );
    if (proactive == NULL)
        return;

    const uint8_t* buffer = (uint8_t*) cmdPdu;
    if (astk_parse_proactive_command(&buffer, proactive) != 0) {
        astk_proactive_command_free(stk, proactive);
    }
}

void
astk_process_command( AStk stk, const char* cmdPdu )
{
    // ** [start] for Debug
    D("Edgar: astk_process_command: %s\n", cmdPdu);
    // ** [end]

    if (!memcmp(cmdPdu, "+CUSATT=", 8)) {
        astk_process_terminal_response(stk, cmdPdu+8);
    }
}
