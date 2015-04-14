/*
 * transport.c 
 *
 * COS461: HW#5 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */

//Inclusions..
#include <iostream>
#include <vector>
   using namespace std;
#include <netinet/in.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

//Packet structure to hold data for resubmission.
   struct packet
   {
      uint8_t* data;
      tcp_seq sequence_num;
      tcp_seq len;
   };

//Network states.
   enum {ESTABLISHED, FIN_WAIT_1, 
      FIN_WAIT_2, CLOSE_WAIT, LAST_ACK, CLOSING}; 
   
//Window indices.
   static tcp_seq next_to_send;
   static tcp_seq next_to_be_acked;
   static tcp_seq next_to_recv;
   
//Sender window size.
   static uint16_t SENDER_WINDOW;
   
//Vectors containing packets received and packets in flight.
   static vector<packet> packetsInFlight;
   static vector<packet> packetsReceived;

#define RECEIVER_WINDOW 3072
#define CONGESTION_WINDOW 3072
#define PAYLOAD_SIZE 536
#define MAX_HEADER_SIZE 60

/* this structure is global to a mysocket descriptor */
   typedef 
      struct
      {
         bool_t done;    /* TRUE once connection is closed */
      
         int connection_state;   /* state of the connection (established, etc.) */
         tcp_seq initial_sequence_num;
      
      /* any other connection-wide global variables go here */
      } context_t;


//Method declarations.
   static void generate_initial_seq_num(context_t *ctx);
   static void control_loop(mysocket_t sd, context_t *ctx);


//Generate and send a SYN packet onto the socket specified.
   static int send_syn_packet(mysocket_t sd, context_t *ctx)
   {
   //Construct the packet header.
      struct tcphdr header;
      header.th_seq = htonl(ctx->initial_sequence_num);
      header.th_ack = htonl(ctx->initial_sequence_num+1);
      header.th_off = 5;
      header.th_flags = TH_SYN;
      header.th_win = htons(RECEIVER_WINDOW);
   
   //Send the packet along.
      if (stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL) != -1)
      {
         cout << "SYN packet sent with sequence number: " << ntohl(header.th_seq) << endl;
         return 1;
      }
      //Print and return 0 if send failed.
      else 
      {
         cout << "Send failed.." << endl;
         return 0;
      }
   }

//Attempt to receive a SYN packet form a peer.
   static uint8_t* receive_syn_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Attempting to receive SYN." << endl;
      unsigned int event;
   
   //Wait for network data.
      event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
   
   //Put the packet into a buffer and construct the header.   
      uint8_t* buf = (uint8_t*)malloc(sizeof(struct tcphdr));
      stcp_network_recv(sd, buf, sizeof(struct tcphdr));
      struct tcphdr* hdr = (struct tcphdr*)buf;
      
   //If the packet was a SYN, set the SENDER_WINDOW to the other side's
   //receiver window.
      if (hdr->th_flags == TH_SYN)
      {
         cout << "SYN packet received."<<endl;
         SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
         return buf;
      }
      else
      {
         cout << "Not a SYN packet.." << endl; 
         return NULL;
      }
   }
   
//Send a SYN-ACK packet to a peer.
   static int send_synack_packet(mysocket_t sd, context_t *ctx, uint8_t* ack)
   {
      cout << "Sending a SYN-ACK packet." << endl;
      
   //Construct the packet.
      struct tcphdr* hdr = (struct tcphdr*)ack;
      hdr->th_ack = htonl(ntohl(hdr->th_seq) + 1);
      hdr->th_seq = htonl(ctx->initial_sequence_num);
      hdr->th_flags = TH_SYN | TH_ACK;
      hdr->th_win = htons(RECEIVER_WINDOW);
   
   //Send it along; return 1 if successful.
      if (stcp_network_send(sd, hdr, sizeof(struct tcphdr), NULL) != -1)
      {
         cout << "SYN-ACK packet sent with ACK number: " << ntohl(hdr->th_ack) << "." << endl;
         return 1;
      }
      else 
      {
         cout << "Send failed." << endl;
         return 0;
      }
   }

//Attempt to receive a SYN-ACK packet from a peer.
   static uint8_t* receive_synack_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Attempting to receive a SYN-ACK packet." << endl;
      unsigned int event;
   
      event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
   
   //Read the packet into a buffer and make the header.
      uint8_t* buf = (uint8_t*)malloc(sizeof(struct tcphdr));
      stcp_network_recv(sd, buf, sizeof(struct tcphdr));
      struct tcphdr* hdr = (struct tcphdr*)buf;
      
   //If the header is a SYN-ACK, set the SENDER_WINDOW
      if (hdr->th_flags == (TH_SYN | TH_ACK))
      {
         cout << "SYN-ACK packet received."<<endl;
         SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
         return buf;
      }
      else
      {
         cout << "Not a SYN-ACK packet.." << endl; 
         return NULL;
      }
   }
   
//Generate an ACK header using the current window indices.
   static struct tcphdr generate_ack_header(mysocket_t sd, context_t *ctx)
   {
      struct tcphdr header;
      header.th_seq = htonl(next_to_send);
      header.th_ack = htonl(next_to_recv);
      header.th_off = 5;
      header.th_flags = TH_ACK;
      header.th_win = htons(RECEIVER_WINDOW);
      
      return header;
   }
   

//Send an ACK packet.
   static int send_ack_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Sending an ACK packet." << endl;
   //Make the ACK header.
      struct tcphdr header = generate_ack_header(sd, ctx);
   
   //Send it along; return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL) != -1)
      {
         cout << "ACK packet send with ACK number: " << ntohl(header.th_ack) << "." <<endl;
         return 1;
      }
      else 
      {
         cout << "Send failed." << endl;
         return 0;
      }
   }
   
//Attempt to receive an ACK packet.
   static uint8_t* receive_ack_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Attempting to receive an ACK packet." << endl;
      unsigned int event;
   
      event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
   
   //Read the packet into a buffer.
      uint8_t* buf = (uint8_t*)malloc(sizeof(struct tcphdr));
      stcp_network_recv(sd, buf, sizeof(struct tcphdr));
      struct tcphdr* hdr = (struct tcphdr*)buf;
      
   //Check if the packet is an ack packet and set SENDER_WINDOW if it is.
      if (hdr->th_flags == TH_ACK)
      {
         cout << "ACK packet received." << endl;
         SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
         return buf;
      }
      else
      {
         cout << "Not an ACK packet." << endl; 
         return NULL;
      }
   }

//Construct and send a FIN packet.
   static int send_fin_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Sending a FIN packet." << endl;
   //Construct the packet.
      struct tcphdr header = generate_ack_header(sd, ctx);
      header.th_flags = TH_FIN;
   
   //Send it along; return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL) != -1)
      {
         cout << "Sent FIN packet." << endl;
         return 1;
      }
      else 
      {
         cout << "Send failed." << endl;
         return 0;
      }
   }











//Send application data.
   static int send_app_data(mysocket_t sd, context_t *ctx)
   {
      cout << "Sending application data." << endl;
   
   //Variable declarations.
      tcp_seq num_can_send = (next_to_be_acked + SENDER_WINDOW) - next_to_send;
      tcp_seq n = 0;
      tcp_seq max_len;
      struct packet pack;
      struct tcphdr header;
      
   //Figure out the right amount to send.
      if (num_can_send > PAYLOAD_SIZE)
         max_len = PAYLOAD_SIZE;
      else
         max_len = num_can_send;
   
   //Malloc the proper amount.
      uint8_t* buf = (uint8_t*)malloc(max_len);
      n = stcp_app_recv(sd, buf, max_len);
   
   //Construct a data packet header.
      header.th_seq = htonl(next_to_send);
      header.th_ack = htonl(next_to_recv + 1);
      header.th_flags = 0;
      header.th_off = 5;
      header.th_win = htons(RECEIVER_WINDOW);
   
   //Create a packet structure.
      pack.data = buf;
      pack.sequence_num = next_to_send;
      pack.len = n;
      
   //Push the packet onto the packetsInFlight array.
      packetsInFlight.push_back(pack);
      next_to_send += n;
      
   //Print the amount of data being sent.
      cout << "Sending " << n << "bytes of data." << endl;
   
   //Send the packet along and return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(header), buf, n, NULL) != -1)
      {
         cout << "Packet sent." << endl;
         return 1;
      }
      else
      {
         cout << "Send failed." << endl;
         return 0;
      }
   }

//Comparison method for packet sequence numbers.
   bool comparePackets(struct packet a, struct packet b)
   {
      return (a.sequence_num < b.sequence_num);
   }

//Method for handling network data.
   static int handle_net_data(mysocket_t sd, context_t *ctx)
   {
   //Put the data in a buffer and initialize a header structure.
      uint8_t* buf = (uint8_t*)malloc(MAX_HEADER_SIZE + PAYLOAD_SIZE);
      tcp_seq n = stcp_network_recv(sd, buf, MAX_HEADER_SIZE + PAYLOAD_SIZE);
      struct tcphdr* hdr = (struct tcphdr*)buf;
      
   //Get the packet size and sequence number.
      tcp_seq header_size = hdr->th_off * 4;
      tcp_seq seq_num = ntohl(hdr->th_seq);
      
   //Create a packet to enqueue.
      struct packet packet;
      packet.sequence_num = seq_num;
      packet.len = n - header_size;
      packet.data = (uint8_t*)malloc(packet.len);
      memcpy(packet.data, buf + header_size, packet.len);
     
      cout << "Header is of length: " << header_size << "." << endl;
      cout << "Packet is of length: " << packet.len << "." << endl;
   
   //If the packet is a FIN packet..
      if (hdr->th_flags & TH_FIN)
      {
         cout << "FIN packet." << endl;
         stcp_fin_received(sd);  
      
         if (ctx->connection_state == FIN_WAIT_1)
         {
            cout << "In FIN_WAIT_1 state -> CLOSING state;"
               << endl << "sending ACK" << endl;
         
         //Create and send the FIN-ACK        
            struct tcphdr header = generate_ack_header(sd, ctx);
            stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL);
         
         //Change the connection state to CLOSING.
            ctx->connection_state = CLOSING;
         }
         
         else if (ctx->connection_state == FIN_WAIT_2)
         {
            cout << "In FIN_WAIT_2 state -> TIME_WAIT state;"
               << endl << "sending ACK" << endl;
            struct tcphdr header = generate_ack_header(sd, ctx);
            stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL);
            
         //CLOSE EVERYTHING.
            ctx->done = true;
         }  
         
         else if (ctx->connection_state == ESTABLISHED)
         {
            cout << "In ESTABLISHED state -> CLOSE_WAIT state;"
               << endl << "sending ACK" << endl;
            struct tcphdr header = generate_ack_header(sd, ctx);
            stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL);
            
            ctx->connection_state = CLOSE_WAIT;
         }
         free(buf);
         return 0;
      }
      
   //If the packet is an ACK packet
      if (hdr->th_flags & TH_ACK)
      {
         cout << "ACK packet." << endl;
      
      //Sort the packetsInFlight vector.
         sort (packetsInFlight.begin(), packetsInFlight.end(), comparePackets);
      
      //While we have packets waiting to be acked < ack number.
         while (packetsInFlight.size() > 0
         && (packetsInFlight[0].sequence_num 
         +  packetsInFlight[0].len <= ntohl(hdr->th_ack)))
         {
         //Increment next_to_be_acked.
            next_to_be_acked = packetsInFlight[0].sequence_num + packetsInFlight[0].len;
            packetsInFlight.erase(packetsInFlight.begin());
         }
         
         if (ctx->connection_state == FIN_WAIT_1)
         {
            cout << "In FIN_WAIT_1 state -> FIN_WAIT_2 state;" << endl;
            ctx->connection_state = FIN_WAIT_2;
         }
         else if (ctx->connection_state == CLOSING)
         {
            cout << "In CLOSING state; closing connection." << endl;
            ctx->done = true;
         }
         else if (ctx->connection_state == LAST_ACK)
         {
            cout << "In LAST_ACK state; closing connection." << endl;
            ctx->done = true;
         }
      //Free the allocated buffer.
         free(buf);
         return 0;
      }
      
      if (packet.len > 0)
      {
         cout << "Data packet." << endl;
         cout << "Sequence number: " << seq_num << "." << endl;
      
         if (seq_num >= (next_to_recv + RECEIVER_WINDOW)
         && (seq_num + packet.len) <= next_to_recv)
         {
            cout << "Data not in recv window." << endl;
         //ACK next_to_recv.
            struct tcphdr ack_header = generate_ack_header(sd, ctx);
            stcp_network_send(sd, &ack_header, sizeof(ack_header), NULL);
         }
         else if (seq_num >= next_to_recv 
          && (seq_num + packet.len) <= (next_to_recv + RECEIVER_WINDOW))
         {
            cout << "Data completely in recv window." << endl;
         
         //Check if data has already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
               if (packetsReceived[i].sequence_num == seq_num)
               {
                  cout << "Repeated data." << endl;
                  free(buf);
                  return 0;
               }
            packetsReceived.push_back(packet);
         }
         else if (seq_num < (next_to_recv))
         {
            cout << "Data overlaps from below." << endl;
         //Create a packet for the truncated data.
            uint8_t* choppedPacket = (uint8_t*)malloc(seq_num + packet.len - next_to_recv);
            memcpy(choppedPacket, packet.data + (next_to_recv - seq_num), 
               seq_num + packet.len - next_to_recv);
            packet.sequence_num = next_to_recv; 
            packet.len = seq_num + packet.len - next_to_recv;
            packet.data = choppedPacket;
         
         //Make sure the data hasn't already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
               if (packetsReceived[i].sequence_num == seq_num)
               {
                  cout << "Repeated data." << endl;
                  free(buf);
                  return 0;
               }
         //Add the packet.
            packetsReceived.push_back(packet);
         }
         else
         {
         //Check if data overlaps from above window.
            cout << "Data overlaps from above." << endl;
         
         //Create a packet for the truncated data.
            uint8_t* choppedPacket = (uint8_t*)malloc((next_to_recv + RECEIVER_WINDOW)
               	    - seq_num);
            memcpy(choppedPacket, packet.data, 
               (next_to_recv + RECEIVER_WINDOW) - seq_num);
            packet.len = (next_to_recv + RECEIVER_WINDOW) - seq_num;
            packet.data = choppedPacket;
         
         //Make sure the packet hasn't already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
               if (packetsReceived[i].sequence_num == seq_num)
               {
                  cout << "Repeated data." << endl;
                  free(buf);
                  return 0;
               }
         
         //Add the packet.
            packetsReceived.push_back(packet);
         }
      
      //Sort the received packets to determine window indices.
         sort (packetsReceived.begin(), packetsReceived.end(), comparePackets);
         
      //Figure out which byte to ack.
         tcp_seq byte_to_ack = next_to_recv;
      
      //Increment byte_to_ack
         if (packetsReceived.size() > 0
         &&  packetsReceived[0].sequence_num == next_to_recv)
         {
            while (packetsReceived.size() > 0
            && packetsReceived[0].sequence_num == byte_to_ack)
            {
               byte_to_ack = byte_to_ack + packetsReceived[0].len;
               stcp_app_send(sd, packet.data, packet.len);
               free(packet.data);
               packetsReceived.erase(packetsReceived.begin());
            }
         }
      
         cout << "ACKing byte: " << byte_to_ack << endl;
         next_to_recv = byte_to_ack;
      
      //Send the ack for the next desired bit.
         struct tcphdr header = generate_ack_header(sd, ctx);
         stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL);     
      }
      free(buf);
      return 1;
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
   
   /* XXX: you should send a SYN packet here if is_active, or wait for one
   * to arrive if !is_active.  after the handshake completes, unblock the
   * application with stcp_unblock_application(sd).  you may also use
   * this to communicate an error condition back to the application, e.g.
   * if connection fails; to do so, just set errno appropriately (e.g. to
   * ECONNREFUSED, etc.) before calling the function.
   */
      if (is_active)
      {
      //Send a SYN packet.
         if(!send_syn_packet(sd, ctx))
            errno = ECONNREFUSED;
      
      //Wait for a SYN-ACK packet.
         uint8_t* buf = receive_synack_packet(sd, ctx);
      
      //Set next_to_recv based on the packet's sequence number.
         next_to_recv = ntohl(((struct tcphdr*)buf)->th_seq) + 1;
            
      //Send an ACK packet.
         if (!send_ack_packet(sd, ctx))
            errno = ECONNREFUSED;
      
      //Set next_to_send and next_to_be_acked based on INS.
         next_to_send = next_to_be_acked = ctx->initial_sequence_num + 1;
         free(buf);
      }
      else
      {
      //Wait for SYN-ACK packet.
         uint8_t* buf = receive_syn_packet(sd, ctx);
      
      //Set next_to_recv based on packet's sequence number.
         next_to_recv = ntohl(((struct tcphdr*)buf)->th_seq) + 1;
      
      //Send a SYN-ACK packet.
         if (!send_synack_packet(sd, ctx, buf))
            errno = ECONNREFUSED;
      
      //Wait for an ACK.
         receive_ack_packet(sd, ctx);
      
      //Set next_to_send and next_to_be_acked based on INS.
         next_to_send = next_to_be_acked = ctx->initial_sequence_num + 1;
         free(buf);
      }
     
      cout << "next_to_recv: " << next_to_recv << endl;
      cout << "next_to_send: " << next_to_send << endl;
      cout << "next to be acked: " << next_to_be_acked << endl;
     
     
   //Set the connection state to ESTABLISHED. 
      ctx->connection_state = ESTABLISHED;
   
   //Unblock the application.
      stcp_unblock_application(sd);
   
   //Enter the control loop.
      control_loop(sd, ctx);
   
   //Notify cause myread() to stop receiving FIN's.
   //stcp_fin_received(sd);
   
   //Clean up.
      free(ctx);
   }


////////////////////////////////////////////////////////////
// Random Number Generator
////////////////////////////////////////////////////////////
   static double RandomNumber(void)
   {
   #ifdef _WIN32
   // Seed random number generator
   static int first = 1;
   if (first) {
    srand(GetTickCount());
    first = 0;
   }
   
   // Return random number
   int r1 = rand();
   double r2 = ((double) rand()) / ((double) RAND_MAX);
   return (r1 + r2) / ((double) RAND_MAX);
   #else 
   // Seed random number generator
      static int first = 1;
      if (first) {
         struct timeval timevalue;
         gettimeofday(&timevalue, 0);
         srand48(timevalue.tv_usec);
         first = 0;
      }
   
   // Return random number
      return drand48();
   #endif
   }



// generate random initial sequence number for an STCP connection
   static void generate_initial_seq_num(context_t *ctx)
   {
      assert(ctx);
   
   #ifdef FIXED_INITNUM
   /* please don't change this! */
   ctx->initial_sequence_num = 1;
   #else
   //See RandomNumber() method from above.
      ctx->initial_sequence_num = (tcp_seq)(RandomNumber() * 255);
      cout << "Random sequence number generated: " << ctx->initial_sequence_num << endl;
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
   
      while (!ctx->done)
      {
         unsigned int event;
         
         cout << endl;
         cout << "Unacked packets: " << packetsInFlight.size() << endl;
         cout << "Unpassed app packets: " << packetsReceived.size() << endl;
      
         cout << "next_to_send: " << next_to_send << endl;
         cout << "next_to_be_acked: " << next_to_be_acked << endl;
         cout << "next_to_recv: " << next_to_recv << endl;
      
         cout << "waiting.." << endl;
      /* see stcp_api.h or stcp_api.c for details of this function */
      /* XXX: you will need to change some of these arguments! */
      
      //If our window is full, don't accept any app data-- introduced
      //randomness to avoid sending small packets for large transfers..
      //It's complicated but necessary; don't worry about it.
         if (next_to_send >= (next_to_be_acked 
            + (tcp_seq)((RandomNumber() * .5 + .5) 
         	       * SENDER_WINDOW) - 1))
            event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED, NULL);
         else
            event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
      
      
      // check whether event was the network, app, or a close request
         if (event & APP_DATA)
         {
            cout << "Application data received."<<endl;
            send_app_data(sd, ctx);
         }
         
         else if (event & NETWORK_DATA)
         {
            cout << "Network data received."<<endl;
            handle_net_data(sd, ctx);
         }
         
         else if (event & APP_CLOSE_REQUESTED)
         {
            cout << "App close requested." << endl;
            if (ctx->connection_state == ESTABLISHED)
            {
            //Send a FIN packet.
               send_fin_packet(sd, ctx);
               ctx->connection_state = FIN_WAIT_1;
            }
            else if (ctx->connection_state == CLOSE_WAIT)
            {
            //Send a FIN packet.
               send_fin_packet(sd, ctx);
               ctx->connection_state = LAST_ACK;
            }
         }
         
         else if (event & TIMEOUT)
         {
            cout << "Timeout occurred." << endl;
         }
         else
            cout << "Other???" << endl;
      /* etc. */
         cout << endl << endl << endl;
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
