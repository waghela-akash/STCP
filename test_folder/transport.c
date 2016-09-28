/*
 * transport.c 
 *
 *	Project 3		
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <sys/time.h>

enum { CSTATE_ESTABLISHED, FIN_SENT, FIN_RECEIVED, CLOSED };    /* you should have more states */

#define debug 0
int window_size = 3072;
int max_payload_len = STCP_MSS;
int MAX_IP_PAYLOAD_LEN = 1500;
/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq sequence_num;

    int advertised_window_size;
    int congestion_window_size;
    int sender_window_size;

    int last_ack_byte;
    int last_sent_byte;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

// Adding a 1 sec increament
timespec timeVal(timeval tv){
    timespec ts;
    (ts).tv_sec = (tv).tv_sec + 1;
    (ts).tv_nsec = (tv).tv_usec * 1000;
    return ts;
}


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->congestion_window_size = window_size;
    ctx->sender_window_size = window_size;
    ctx->advertised_window_size = window_size;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

     // Convert Time for all the subsequent waits.
    unsigned int event;
    timeval tv;
    timespec ts;
    if(is_active){
        STCPHeader synHeader;
        synHeader.th_seq = ctx->initial_sequence_num;
        synHeader.th_flags = TH_SYN;
        int size = stcp_network_send(sd,&synHeader,sizeof(synHeader),NULL);
        
        gettimeofday(&tv,0);
        ts = timeVal(tv);
        event = stcp_wait_for_event(sd, ANY_EVENT, &ts);

        if(event & NETWORK_DATA){

            STCPHeader *recvSynAckHeader;
            recvSynAckHeader = (STCPHeader *) malloc(sizeof(STCPHeader));
            char recv[MAX_IP_PAYLOAD_LEN];
            stcp_network_recv(sd,recv,sizeof(recv));
            recvSynAckHeader = (STCPHeader *)recv;

            if(recvSynAckHeader->th_flags & (TH_SYN || TH_ACK)){
                if(recvSynAckHeader->th_ack==synHeader.th_seq+1){
                    STCPHeader ackHeader;
                    ackHeader.th_flags = TH_ACK;
                    ackHeader.th_ack = recvSynAckHeader->th_seq + 1;
                    stcp_network_send(sd,&ackHeader,sizeof(ackHeader),NULL);

                    ctx->sequence_num = ctx->initial_sequence_num + 1; 
                    ctx->last_ack_byte = ctx->sequence_num;
                    ctx->last_sent_byte = ctx->initial_sequence_num; 
                }
                else{
                    printf("Active Ack Mismatch\n");
                    exit(0);
                }
            }
            else{
                printf("Active Flag Mismatch\n");
                exit(0);
            }            
        }
        else{
            printf("Active Unexpected Event\n");
            exit(0);
        }
     }
     else{
        if(debug)
            printf("PASSIVE\n");

        unsigned int event;
        timeval tv;
        gettimeofday(&tv,0);
        timespec ts = timeVal(tv);
        event = stcp_wait_for_event(sd, ANY_EVENT, &ts);

        if(event & NETWORK_DATA){
            STCPHeader *recvSynHeader;
            recvSynHeader = (STCPHeader *)malloc(sizeof(STCPHeader));
            char recv[MAX_IP_PAYLOAD_LEN];
            stcp_network_recv(sd,recv,sizeof(recv));

            recvSynHeader = (STCPHeader *)recv;

            STCPHeader synAckHeader;
            synAckHeader.th_seq = ctx->initial_sequence_num;
            synAckHeader.th_ack = recvSynHeader->th_seq + 1;
            synAckHeader.th_flags = (TH_SYN || TH_ACK);
            stcp_network_send(sd,&synAckHeader,sizeof(synAckHeader),NULL);

            gettimeofday(&tv,0);
            ts = timeVal(tv);
            event = stcp_wait_for_event(sd, ANY_EVENT, &ts);

            if(event & NETWORK_DATA){
                STCPHeader *recvAckHeader;
                recvAckHeader = (STCPHeader *)malloc(sizeof(STCPHeader));
                char recv[MAX_IP_PAYLOAD_LEN];
                stcp_network_recv(sd,recv,sizeof(recv));
                recvAckHeader = (STCPHeader *)recv;
                if(recvAckHeader->th_flags & TH_ACK){
                    if(recvAckHeader->th_ack!=synAckHeader.th_seq+1){
                        printf("Passive Ack Mismatch\n");
                        exit(0);
                    }
                    ctx->sequence_num = ctx->initial_sequence_num + 1;
                    ctx->last_ack_byte = ctx->sequence_num;
                    ctx->last_sent_byte = ctx->initial_sequence_num;
                }
                else{
                    printf("Passive Flag Mismatch\n");
                    exit(0);
                }
            }
        }
        else{
            printf("Unexpected Event\n");
            exit(0);
        }
     }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);
    if(debug)
        printf("Handshake done\n");
    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    srand((unsigned)time(NULL));
    ctx->initial_sequence_num = 15;//rand()%256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        timeval tv;
        gettimeofday(&tv,0);
        timespec ts = timeVal(tv);
        event = stcp_wait_for_event(sd, ANY_EVENT, &ts);

        if(debug){
            printf("-----------> New Event Type %d <-----------\n",event);
            printf("Curr State %d\n",ctx->connection_state);
            printf("Curr Seq Number %d\n",ctx->sequence_num);
            printf("LSB: %d LAB: %d\n",ctx->last_sent_byte,ctx->last_ack_byte);
        } 
            

        /* check whether it was the network, app, or a close request */
        if ((event & APP_DATA) && (ctx->connection_state != FIN_SENT))
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */

            char read[max_payload_len];
            memset(read,0,sizeof(read));
            int size;
            int sent_size;
            sent_size = MIN(ctx->congestion_window_size, ctx->sender_window_size);            
            sent_size = MIN(sent_size, max_payload_len);

            if(debug){
                printf("congestion %d sender %d\n",ctx->congestion_window_size, ctx->sender_window_size);
            }
            assert(sent_size>0);
            
            size = stcp_app_recv(sd, read, sent_size);

            if(debug)
                printf("Seq Num: %d App read size: %d\n",ctx->sequence_num,size);

            STCPHeader msgHeader;
            msgHeader.th_seq = ctx->sequence_num;
            msgHeader.th_off = sizeof(msgHeader)/4;
            msgHeader.th_win = ctx->advertised_window_size - size;
            msgHeader.th_ack = ctx->last_ack_byte;
            msgHeader.th_flags = 0;

            if(stcp_network_send(sd,&msgHeader,sizeof(msgHeader),&read,size,NULL)>0){
                ctx->advertised_window_size = msgHeader.th_win;
                ctx->sequence_num = ctx->sequence_num + size;
                ctx->last_sent_byte = ctx->sequence_num - 1;
                //ctx->congestion_window_size -= (size+sizeof(msgHeader));
            }
        }

        if ((event & APP_CLOSE_REQUESTED) && (ctx->connection_state != FIN_SENT))
        {
            if(ctx->connection_state==FIN_RECEIVED)
                ctx->connection_state=CLOSED;
            else
                ctx->connection_state = FIN_SENT;

            if(debug)
                printf("FIN sending...\n");
            
            STCPHeader msgHeader;
            msgHeader.th_flags = TH_FIN;
            msgHeader.th_seq = ctx->sequence_num;
            msgHeader.th_off = sizeof(msgHeader)/4;
            msgHeader.th_win = ctx->advertised_window_size;
            msgHeader.th_ack = ctx->last_ack_byte;

            stcp_network_send(sd,&msgHeader,sizeof(msgHeader),NULL);
        }

        if (event & NETWORK_DATA)
        {
            
            STCPHeader *readMsgHeader;            
            readMsgHeader = (STCPHeader *)malloc(sizeof(STCPHeader));

            char recv[MAX_IP_PAYLOAD_LEN];
            memset(recv,0,sizeof(recv));
            int size = stcp_network_recv(sd,recv,sizeof(recv));
            readMsgHeader = (STCPHeader *)recv;

            int offset = readMsgHeader->th_off;
            offset = offset*4;
            
            if(debug){
                printf("NETWORK_DATA Asking For...\n");
                printf("Type of Request %d\n",readMsgHeader->th_flags);
                printf("Seq No: %d Ack For: %d\n",readMsgHeader->th_seq, readMsgHeader->th_ack);
                printf("Received: %d, Offset: %d, recv+offset: %s\n",size,offset,recv+offset);                
            }
            assert(size >= offset);
            if(size<0)
                continue;
            if(readMsgHeader->th_flags & TH_ACK){
                if(debug)
                    printf("Got Ack for %d\n",readMsgHeader->th_ack);
                ctx->sender_window_size = readMsgHeader->th_win;
                ctx->advertised_window_size += (readMsgHeader->th_ack - ctx->last_ack_byte);
                ctx->last_ack_byte = readMsgHeader->th_ack;               
            }
            else if(readMsgHeader->th_flags & TH_FIN){
                /*
                if(ctx->connection_state!=FIN_SENT){
                    STCPHeader *finMsgHeader;
                    finMsgHeader = (STCPHeader *)malloc(sizeof(STCPHeader));
                    finMsgHeader->th_flags = TH_FIN;
                    finMsgHeader->th_ack = readMsgHeader->th_seq + (size-offset);
                    finMsgHeader->th_off = sizeof(STCPHeader)/4;
                    finMsgHeader->th_win = ctx->advertised_window_size;
                    finMsgHeader->th_seq = ctx->sequence_num;

                    stcp_network_send(sd,finMsgHeader,sizeof(STCPHeader),NULL);
                    if(debug)
                        printf("Sent FIN/FIN-ACK for %d\n",readMsgHeader->th_seq);
                }
                */
                if(ctx->connection_state==FIN_SENT)
                    ctx->connection_state=CLOSED;
                else
                    ctx->connection_state = FIN_RECEIVED;

                STCPHeader *ackMsgHeader;
                ackMsgHeader = (STCPHeader *)malloc(sizeof(STCPHeader));
                ackMsgHeader->th_flags = TH_ACK;
                ackMsgHeader->th_ack = readMsgHeader->th_seq + (size-offset) + 1;
                ackMsgHeader->th_off = sizeof(STCPHeader)/4;
                ackMsgHeader->th_win = ctx->advertised_window_size;
                ackMsgHeader->th_seq = ctx->sequence_num;

                stcp_fin_received(sd);
                stcp_network_send(sd,ackMsgHeader, sizeof(STCPHeader),NULL); 
                if(debug)
                    printf("Sent ACK/FIN-ACK for %d\n",readMsgHeader->th_seq);             
            }
            else{
                
                STCPHeader ackMsgHeader;
                //ackMsgHeader = (STCPHeader *)malloc(sizeof(STCPHeader));
                ackMsgHeader.th_flags = TH_ACK;
                ackMsgHeader.th_ack = readMsgHeader->th_seq + (size-offset);
                ackMsgHeader.th_off = (uint8_t)sizeof(STCPHeader)/4;
                ackMsgHeader.th_win = ctx->advertised_window_size;
                ackMsgHeader.th_seq = ctx->sequence_num;

                if(debug){
                    printf("Sent Ack for %d %d\n",readMsgHeader->th_seq,ackMsgHeader.th_ack);
                    printf("%d %d %d\n",ackMsgHeader.th_off, ackMsgHeader.th_seq, ackMsgHeader.th_flags);
                }

                stcp_network_send(sd,&ackMsgHeader, sizeof(STCPHeader),NULL);
            }
            stcp_app_send(sd,recv+offset,size-offset);

            if((ctx->connection_state==CLOSED) && 
                (ctx->last_ack_byte==ctx->last_sent_byte+2)){
                ctx->done=1;
            }
            if(debug && ctx->connection_state==CLOSED){
                printf("HOLA %d %d\n",ctx->last_sent_byte,ctx->last_ack_byte);
            } 
        }       
        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



