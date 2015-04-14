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
#include <openssl/sha.h>
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
      struct timespec time_expires;
      struct timespec time_sent;
      int num_sent;
      bool is_fin;
   };

//Network states.
   enum {ESTABLISHED, FIN_WAIT_1, 
      FIN_WAIT_2, CLOSE_WAIT, LAST_ACK, CLOSING, TIME_WAIT}; 
   
//Window indices.
   static tcp_seq next_to_send;
   static tcp_seq next_to_be_acked;
   static tcp_seq next_to_recv;
	
   
   
   static struct timespec ESTIMATED_RTT;  
   static struct timespec before;  
   static struct timespec after; 
   static struct timespec diff;   
	
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

   struct  timespec  tsAdd (struct  timespec  time1,
        struct  timespec  time2)
   {
      struct  timespec  result ;
   /* Add the two times together. */
   
      result.tv_sec = time1.tv_sec + time2.tv_sec ;
      result.tv_nsec = time1.tv_nsec + time2.tv_nsec ;
      if (result.tv_nsec >= 1000000000L) 
      {		/* Carry? */
         result.tv_sec++ ;  result.tv_nsec = result.tv_nsec - 1000000000L ;
      }
   
      return (result) ;
   }
	
   struct  timespec  tsSubtract (struct  timespec  time1,
        struct  timespec  time2)
   {    /* Local variables. */
      struct  timespec  result;
   
   /* Subtract the second time from the first. */
   
      if ((time1.tv_sec < time2.tv_sec) ||
        ((time1.tv_sec == time2.tv_sec) &&
         (time1.tv_nsec <= time2.tv_nsec))) {		/* TIME1 <= TIME2? */
         result.tv_sec = result.tv_nsec = 0 ;
      } 
      else {						/* TIME1 > TIME2 */
         result.tv_sec = time1.tv_sec - time2.tv_sec ;
         if (time1.tv_nsec < time2.tv_nsec) {
            result.tv_nsec = time1.tv_nsec + 1000000000L - time2.tv_nsec ;
            result.tv_sec-- ;				/* Borrow a second. */
         } 
         else {
            result.tv_nsec = time1.tv_nsec - time2.tv_nsec ;
         }
      }
   
      return (result) ;
   
   }


   static struct timespec get_time()
   {
      struct timeval tv;
      struct timespec ts;
      struct timezone tz;
      
      gettimeofday(&tv, &tz);
      
      ts.tv_sec = tv.tv_sec;
      ts.tv_nsec = tv.tv_usec * 1000;
      
      return ts;
   }
	
   static struct timespec get_expiration()
   {
      struct timespec ts;
      
      ts = get_time();
   	
      if (ESTIMATED_RTT.tv_sec >= 3)
         ESTIMATED_RTT.tv_sec = 3;
      else if (ESTIMATED_RTT.tv_nsec < 1000000)
         ESTIMATED_RTT.tv_nsec = 1000000;
   	
   	
      ts = tsAdd(ts, ESTIMATED_RTT);
      ts = tsAdd(ts, ESTIMATED_RTT); 
   	 
   	   	
      return ts;
   }


//Generate and send a SYN packet onto the socket specified.
   static int send_syn_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Sent SYN packet." << endl;
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
         //CCC << "SYN packet sent with sequence number: " << ntohl(header.th_seq) << endl;
         return 1;
      }
      //Print and return 0 if send failed.
      else 
      {
         //CCC << "Send failed.." << endl;
         return 0;
      }
   }

	//Attempt to receive a SYN packet form a peer.
   static uint8_t* receive_syn_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Received SYN packet." << endl;
      //CCC << "Attempting to receive SYN." << endl;
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
         //CCC << "SYN packet received."<<endl;
         SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
         return buf;
      }
      else
      {
         //CCC << "Not a SYN packet.." << endl; 
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
         //CCC << "SYN-ACK packet sent with ACK number: " << ntohl(hdr->th_ack) << "." << endl;
         return 1;
      }
      else 
      {
         //CCC << "Send failed." << endl;
         return 0;
      }
   }

	//Attempt to receive a SYN-ACK packet from a peer.
   static uint8_t* receive_synack_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Attempting to receive a SYN-ACK packet." << endl;
      unsigned int event;
   
      struct timespec ts = get_time();
      
      ts.tv_sec += 1;
   
      event = stcp_wait_for_event(sd, NETWORK_DATA, &ts);
   
      if (event != TIMEOUT)
      {
      //Read the packet into a buffer and make the header.
         uint8_t* buf = (uint8_t*)malloc(sizeof(struct tcphdr));
         stcp_network_recv(sd, buf, sizeof(struct tcphdr));
         struct tcphdr* hdr = (struct tcphdr*)buf;
      
      //If the header is a SYN-ACK, set the SENDER_WINDOW
         if (hdr->th_flags == (TH_SYN | TH_ACK))
         {
            //CCC << "SYN-ACK packet received."<<endl;
            SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
            return buf;
         }
         else
         {
            //CCC << "Not a SYN-ACK packet.." << endl; 
            free(buf);
            return NULL;
         }
      }
      else
      {
         //CCC << "Syn timed out." << endl;
         return NULL;
      }
   }
   
	//Generate an ACK header using the current window indices.
   static struct tcphdr generate_ack_header(mysocket_t sd)
   {
      cout << "ACKing byte " << next_to_recv << endl;
   
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
      //CCC << "Sending an ACK packet." << endl;
      //Make the ACK header.
      struct tcphdr header = generate_ack_header(sd);
   
   	//Send it along; return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL) != -1)
      {
         //CCC << "ACK packet send with ACK number: " << ntohl(header.th_ack) << "." <<endl;
         return 1;
      }
      else 
      {
         //CCC << "Send failed." << endl;
         return 0;
      }
   }
   
	//Attempt to receive an ACK packet.
   static uint8_t* receive_ack_packet(mysocket_t sd, context_t *ctx)
   {
      //CCC << "Attempting to receive an ACK packet." << endl;
      unsigned int event;
   
      struct timespec ts = get_time();
   	
      ts.tv_sec += 1;
   
      event = stcp_wait_for_event(sd, NETWORK_DATA, &ts);
   
      if (event != TIMEOUT)
      {
      //Read the packet into a buffer.
         uint8_t* buf = (uint8_t*)malloc(sizeof(struct tcphdr));
         stcp_network_recv(sd, buf, sizeof(struct tcphdr));
         struct tcphdr* hdr = (struct tcphdr*)buf;
      
      //Check if the packet is an ack packet and set SENDER_WINDOW if it is.
         if (hdr->th_flags & TH_ACK)
         {
            //CCC << "ACK packet received." << endl;
            SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
            return buf;
         }
         else
         {
            //CCC << "Not an ACK packet." << endl; 
            free(buf);
            return NULL;
         }
      }
      else
      {
         //CCC << "Synack timed out." << endl;
         return NULL;
      }
   }


//Construct and send a FIN packet.
   static int send_fin_packet(mysocket_t sd, context_t *ctx)
   {
      cout << "Sending a FIN packet seqno: " << next_to_send << endl;
      //Construct the packet.
      struct tcphdr header = generate_ack_header(sd);
      header.th_flags = TH_FIN;  
   	
      struct packet packet;
      bzero(&packet, sizeof(struct packet));
   	
      packet.sequence_num = next_to_send;
      packet.data = (uint8_t*)malloc(1);
      packet.len = 1;
      packet.is_fin = true;
      packet.num_sent = 1;
      packet.time_expires = get_expiration();
      packet.time_sent = get_time();
   	
      packetsInFlight.push_back(packet);
      next_to_send++;
   
   	//Send it along; return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL) != -1)
      {
         //CCC << "Sent FIN packet." << endl;
         return 1;
      }
      else 
      {
         //CCC << "Send failed." << endl;
         return 0;
      }
   }


/***************************************************************/
/***************************************************************/
/***************************************************************/
/***************************************************************/
/***************************************************************/
/***************************************************************/

   bool compare_seq(struct packet a, struct packet b)
   {
      return (a.sequence_num < b.sequence_num);
   }
   bool compare_expiration(struct packet a, struct packet b)
   {
      diff = tsSubtract(a.time_expires, b.time_expires);
      if (diff.tv_sec < 0)
         return true;
      else if (diff.tv_sec == 0
      	  &&	diff.tv_nsec < 0)
         return true;
      else
         return false;
   }





   static void resend_all_packets(mysocket_t sd)
   {
      cout << "Retransmitting......" << endl;
   	
      sort(packetsInFlight.begin(), packetsInFlight.end(), compare_seq);
      for (unsigned int i = 0; i < packetsInFlight.size(); i++)
      {
         struct tcphdr header;
      
         cout << "Sequence number: " << packetsInFlight[i].sequence_num << endl;
         cout << "         number of times sent: " << packetsInFlight[i].num_sent << endl;
      //Construct a data packet header.
         header.th_seq = htonl(packetsInFlight[i].sequence_num);
         header.th_ack = htonl(next_to_recv);
         header.th_flags = TH_ACK;
         header.th_off = 5;
         header.th_win = htons(RECEIVER_WINDOW);
      
         if (packetsInFlight[i].is_fin)
            header.th_flags = TH_FIN;
      
         stcp_network_send(sd, &header, sizeof(header), packetsInFlight[i].data,
            				packetsInFlight[i].len, NULL);
      						
         packetsInFlight[i].num_sent++;
      	
         diff = tsSubtract(packetsInFlight[i].time_expires, packetsInFlight[i].time_sent);
      	//expiration_time = current_time + 2*old_timeout
         packetsInFlight[i].time_expires = tsAdd(get_time(), tsAdd(diff, diff));
         packetsInFlight[i].time_sent = get_time();
      }
   }

	//Send application data.
   static int send_app_data(mysocket_t sd, context_t *ctx)
   {
      //CCC << "Sending application data." << endl;
   	//Variable declarations.
      tcp_seq num_can_send = (next_to_be_acked + SENDER_WINDOW) - next_to_send;
      tcp_seq n = 0;
      tcp_seq max_len;
      struct packet pack;
      struct tcphdr header;
      
      bzero(&pack, sizeof(struct packet));
   	
   	//Figure out the right amount to send.
      if (num_can_send > PAYLOAD_SIZE)
         max_len = PAYLOAD_SIZE;
      else
         max_len = num_can_send;
   	
      if (max_len <= 0)
         return 1;
   	
   	//Malloc the proper amount.
      uint8_t* buf = (uint8_t*)malloc(max_len);
      n = stcp_app_recv(sd, buf, max_len);
   
   	//Construct a data packet header.
      header.th_seq = htonl(next_to_send);
      header.th_ack = htonl(next_to_recv);
      header.th_flags = TH_ACK;
      header.th_off = 5;
      header.th_win = htons(RECEIVER_WINDOW);
   
   	//Create a packet structure.
      pack.data = buf;
      pack.sequence_num = next_to_send;
      pack.len = n;
      pack.time_expires = get_expiration();
      pack.time_sent = get_time();
      pack.num_sent = 1;
      
   	//Push the packet onto the packetsInFlight array.
      //pack.is_fin = false;
      packetsInFlight.push_back(pack);
      next_to_send += n;
      
   	//Print the amount of data being sent.
      //CCC << "Sending " << n << "bytes of data." << endl;
   	
   	//Send the packet along and return 1 if successful.
      if (stcp_network_send(sd, &header, sizeof(header), buf, n, NULL) != -1)
      {
         cout << "Sequence number: " << pack.sequence_num << endl;
         cout << "         length: " << pack.len << endl;
      
         return 1;
      }
      else
      {
         //CCC << "Send failed." << endl;
         return 0;
      }
   }

		//Comparison method for packet sequence numbers.
   static void update_received(mysocket_t sd, context_t *ctx)
   {
      cout << "Updating nex_to_recv from " << next_to_recv << " to ";
   	//Sort the received packets to determine window indices.
      sort (packetsReceived.begin(), packetsReceived.end(), compare_seq);
      	
      	//Increment byte_to_ack
      while (packetsReceived.size() > 0
            && packetsReceived[0].sequence_num <= next_to_recv)
      {
         next_to_recv += packetsReceived[0].len;
         if (packetsReceived[0].is_fin)
         {
            stcp_fin_received(sd);
            
            if (ctx->connection_state == FIN_WAIT_1)
               ctx->connection_state = CLOSING;
            if (ctx->connection_state == FIN_WAIT_2)
               ctx->done = true;
            if (ctx->connection_state == ESTABLISHED)
               ctx->connection_state = CLOSE_WAIT;
         }
         else
            stcp_app_send(sd, packetsReceived[0].data, packetsReceived[0].len);
         
         free(packetsReceived[0].data); //WATCH FOR THIS
         packetsReceived.erase(packetsReceived.begin());
      }
      cout << next_to_recv << endl;
         //CCC << "ACKing byte: " << next_to_recv << endl;
   		
      	//Send the ack for the next desired byte. 
   }

   static void update_next_ack(mysocket_t sd, context_t *ctx, struct tcphdr* hdr)
   {
      cout << "Updating next_to_be_acked from " << next_to_be_acked << "to ";
   	//While we have packets waiting to be acked < ack number.
      while (packetsInFlight.size() > 0
         && (packetsInFlight[0].sequence_num 
         +  packetsInFlight[0].len <= ntohl(hdr->th_ack)))
      {
            //Increment next_to_be_acked.
         next_to_be_acked = packetsInFlight[0].sequence_num + packetsInFlight[0].len;
         	
         if (packetsInFlight[0].num_sent == 1)
         {
         	//UPDATE THE ESTIMATED_RTT
            before = packetsInFlight[0].time_sent;
            after = get_time();
            diff = tsSubtract(after, before);
         
            struct timespec temp1 = ESTIMATED_RTT;
            struct timespec temp2 = diff;
         
            temp1.tv_nsec = temp1.tv_nsec >> 1; //alpha = .5
            temp2.tv_nsec = temp2.tv_nsec >> 1; //1 - alpha = .5
         
            ESTIMATED_RTT = tsAdd(temp1, temp2);
         }
         
         if (packetsInFlight[0].is_fin)
         {
            if (ctx->connection_state == FIN_WAIT_1)
               ctx->connection_state = FIN_WAIT_2;
            if (ctx->connection_state == LAST_ACK)
               ctx->done = true;
            if (ctx->connection_state == CLOSING)
               ctx->done = true;
         }
         
         //CCC << ESTIMATED_RTT.tv_sec <<" " <<ESTIMATED_RTT.tv_nsec << endl;	
         free(packetsInFlight[0].data); //WATCH FOR THIS
         packetsInFlight.erase(packetsInFlight.begin());
      }
      cout << next_to_be_acked << endl;
   }

	//Method for handling network data.
   static int handle_net_data(mysocket_t sd, context_t *ctx)
   {
   	//Put the data in a buffer and initialize a header structure.
      uint8_t* buf = (uint8_t*)malloc(MAX_HEADER_SIZE + PAYLOAD_SIZE);
      tcp_seq n = stcp_network_recv(sd, buf, MAX_HEADER_SIZE + PAYLOAD_SIZE);
      struct tcphdr* hdr = (struct tcphdr*)buf;
      
      cout << ntohl(hdr->th_win) << endl;
   	
      if (n == 0)
      {
         //CCC << "Data is of length 0.." << endl;
         free(buf);
         return 0;
      }
   	
   	//Get the packet size and sequence number.
      tcp_seq header_size = hdr->th_off * 4;
      tcp_seq seq_num = ntohl(hdr->th_seq);
      
   	//Create a packet to enqueue.
      struct packet packet;
      
      bzero(&packet, sizeof(struct packet));
   	
      packet.sequence_num = seq_num;
      packet.len = n - header_size;
      packet.data = (uint8_t*)malloc(packet.len);
      //packet.is_fin = false;
      memcpy(packet.data, buf + header_size, packet.len);
     
      if (hdr->th_flags == (TH_SYN | TH_ACK))
      {
            //CCC << "SYN-ACK packet received."<<endl;
         SENDER_WINDOW = MIN(CONGESTION_WINDOW, ntohs(hdr->th_win));
         
         send_ack_packet(sd, ctx);  
      	
         free(buf);
         return 1;
      }
   
     
     
     
   	//If the packet is a FIN packet..
      if (hdr->th_flags & TH_FIN)
      {
         //CCC << "FIN packet." << endl;
        // stcp_fin_received(sd); 
         packet.is_fin = true;
      }
      
   	
   	//If the packet is an ACK packet
      if (hdr->th_flags & TH_ACK)
      {
         //CCC << "ACK packet." << endl;
      	
      	//Sort the packetsInFlight vector.
         sort (packetsInFlight.begin(), packetsInFlight.end(), compare_seq);
         cout << "Received an ACK for " << ntohl(hdr->th_ack) << endl;
         update_next_ack(sd, ctx, hdr);      
      	
      }
   	
   	
      if (packet.len > 0)
      {
         //CCC << "Data packet." << endl;
         //CCC << "Sequence number: " << seq_num << "." << endl;
         cout << "Receivd a data packet seqno: " << seq_num <<endl;
         cout << "		length: " << packet.len <<endl;
         if (seq_num >= (next_to_recv + RECEIVER_WINDOW) || (seq_num + packet.len) <= next_to_recv)
         {
            cout << "		Data not in recv window." << endl;
         	//ACK next_to_recv.=
         }
         else if (seq_num >= next_to_recv && (seq_num + packet.len) <= (next_to_recv + RECEIVER_WINDOW))
         {
            cout << "		Data completely in recv window." << endl;
         	
            int repeated = 0;
         	//Check if data has already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
            {
               if (seq_num == packetsReceived[i].sequence_num
               &&  packet.len == packetsReceived[i].len)
               {
                  cout << "				Repeated segment." << endl;
                  repeated = 1;
               }
               
               else if (seq_num >= packetsReceived[i].sequence_num
               && seq_num < (packetsReceived[i].sequence_num + packetsReceived[i].len))
               {
                  //CCC << "Overlapping data already received." << endl;
                  int offset = (seq_num + packet.len - 
                  							packetsReceived[i].sequence_num);
                  uint8_t* buf = (uint8_t*)malloc(packetsReceived[i].len - 
                  							offset);
                  memcpy(buf, packetsReceived[i].data + offset, 
                     		packetsReceived[i].len - offset);
                  free(packetsReceived[i].data);
                  packetsReceived[i].data = buf;
                  packetsReceived[i].len = packetsReceived[i].len - offset;
                  packetsReceived[i].sequence_num = packetsReceived[i].sequence_num + offset;
               }
            	
            }
            if (!repeated)
               packetsReceived.push_back(packet);
         }
         else if (seq_num < (next_to_recv))
         {
            cout << "		Data overlaps from below." << endl;
         	//Create a packet for the truncated data.
            uint8_t* choppedPacket = (uint8_t*)malloc(seq_num + packet.len - next_to_recv);
            memcpy(choppedPacket, packet.data + (next_to_recv - seq_num), 
               seq_num + packet.len - next_to_recv);
            packet.sequence_num = next_to_recv; 
            packet.len = seq_num + packet.len - next_to_recv;
            free(packet.data);
            packet.data = choppedPacket;
         
         	//Make sure the data hasn't already been received.
            int repeated = 0;
         	//Check if data has already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
            {
               if (seq_num == packetsReceived[i].sequence_num
               &&  packet.len == packetsReceived[i].len)
               {
                  cout << "			Repeated segment." << endl;
                  repeated = 1;
               }
               else if (seq_num >= packetsReceived[i].sequence_num
               && seq_num < (packetsReceived[i].sequence_num + packetsReceived[i].len))
               {
                  //CCC << "Overlapping data already received." << endl;
                  int offset = (seq_num + packet.len - 
                  							packetsReceived[i].sequence_num);
                  uint8_t* buf = (uint8_t*)malloc(packetsReceived[i].len - 
                  							offset);
                  memcpy(buf, packetsReceived[i].data + offset, 
                     		packetsReceived[i].len - offset);
                  free(packetsReceived[i].data);
                  packetsReceived[i].data = buf;
                  packetsReceived[i].len = packetsReceived[i].len - offset;
                  packetsReceived[i].sequence_num = packetsReceived[i].sequence_num + offset;
               }
            	
            }
            if (!repeated)
               packetsReceived.push_back(packet);
         }
         
         else
         {
         	//Check if data overlaps from above window.
            //CCC << "Data overlaps from above." << endl;
         	
         	//Create a packet for the truncated data.
            uint8_t* choppedPacket = (uint8_t*)malloc((next_to_recv + RECEIVER_WINDOW)
            		       - seq_num);
            memcpy(choppedPacket, packet.data, 
               (next_to_recv + RECEIVER_WINDOW) - seq_num);
            packet.len = (next_to_recv + RECEIVER_WINDOW) - seq_num;
            free(packet.data);
            packet.data = choppedPacket;
         	
         	//Make sure the data hasn't already been received.
            int repeated = 0;
         	//Check if data has already been received.
            for (unsigned int i = 0; i < packetsReceived.size(); i++)
            {
               if (seq_num == packetsReceived[i].sequence_num
               &&  packet.len == packetsReceived[i].len)
               {
                  cout << "			Repeated segment." << endl;
                  repeated = 1;
               }
               
               else if (seq_num >= packetsReceived[i].sequence_num
               && seq_num < (packetsReceived[i].sequence_num + packetsReceived[i].len))
               {
                  //CCC << "Overlapping data already received." << endl;
                  int offset = (seq_num + packet.len - 
                  							packetsReceived[i].sequence_num);
                  uint8_t* temp = (uint8_t*)malloc(packetsReceived[i].len - 
                  							offset);
                  memcpy(temp, packetsReceived[i].data + offset, 
                     		packetsReceived[i].len - offset);
                  free(packetsReceived[i].data);
                  packetsReceived[i].data = temp;
                  packetsReceived[i].len = packetsReceived[i].len - offset;
                  packetsReceived[i].sequence_num = packetsReceived[i].sequence_num + offset;
               }
            	
            }
            if (!repeated)
               packetsReceived.push_back(packet);
         }
         
         update_received(sd, ctx);
         struct tcphdr header = generate_ack_header(sd);
         stcp_network_send(sd, &header, sizeof(struct tcphdr), NULL);
      }
      
   	
   	
      free(buf);
      return 1;
   }

/*
    unsigned char ibuf[] = "compute sha1";
    unsigned char obuf[20];

    SHA1(ibuf, strlen(ibuf), obuf);

    int i;
    for (i = 0; i < 20; i++) {
        printf("%02x ", obuf[i]);
    }
    printf("\n");

    return 0;
*/	





/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
   void transport_init(mysocket_t sd, bool_t is_active)
   {   
   /* XXX: you should send a SYN packet here if is_active, or wait for one
   * to arrive if !is_active.  after the handshake completes, unblock the
   * application with stcp_unblock_application(sd).  you may also use
   * this to communicate an error condition back to the application, e.g.
   * if connection fails; to do so, just set errno appropriately (e.g. to
   * ECONNREFUSED, etc.) before calling the function.
   */
      bzero(&ESTIMATED_RTT, sizeof(struct timespec));
   
      if (is_active)
      {
         context_t *ctx;
      
         ctx = (context_t *) calloc(1, sizeof(context_t));
         assert(ctx);
      
         generate_initial_seq_num(ctx);
      
      
         uint8_t* buf;  
      	
      	//Send a SYN packet.
         for (int i = 0; i < 6; i++)
         {
            before = get_time();  
            
            if(!send_syn_packet(sd, ctx))
               errno = ECONNREFUSED;
            //Wait for a SYN-ACK packet.
            buf = receive_synack_packet(sd, ctx);
            
            after = get_time();
            
            if (buf != NULL)
               break;
            //CCC << "Retrying syn.." << endl;
         }
         if (buf == NULL)
         {
            cout << "Catastrophic network failure; closing connection. 1" << endl;
            errno = ECONNREFUSED;
            return;
         }     	
      	
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
      	context_t *ctx;
   
      	ctx = (context_t *) calloc(1, sizeof(context_t));
      	assert(ctx);
   
      	generate_initial_seq_num(ctx);
      
      
      
      
      	//Wait for SYN-ACK packet.
         uint8_t* buf = receive_syn_packet(sd, ctx);
         uint8_t* temp;
      	
      	//Set next_to_recv based on packet's sequence number.
         next_to_recv = ntohl(((struct tcphdr*)buf)->th_seq) + 1;
      	
         for (int i = 0; i < 6; i++)
         {
         //Send a SYN-ACK packet.
            before = get_time();
         
            uint8_t ack[sizeof(struct tcphdr)];
            memcpy((void*)ack, buf, sizeof(struct tcphdr));
            if (!send_synack_packet(sd, ctx, ack))
               errno = ECONNREFUSED;
            
         //Wait for an ACK.
            temp = receive_ack_packet(sd, ctx);
            
            after = get_time();
         	
            if (temp != NULL)
               break;
         }
         if (temp == NULL)
         {
            cout << "Catastrophic network failure; closing connection. 2" << endl;
            errno = ECONNREFUSED;
            return;
         }
      	
      	//Set next_to_send and next_to_be_acked based on INS.
         next_to_send = next_to_be_acked = ctx->initial_sequence_num + 1;
         free(temp);
         free(buf);
      }
      
      ESTIMATED_RTT = tsSubtract(after, before);
   	
   	//CCC << "Estimated RTT: ";
      //CCC << ESTIMATED_RTT.tv_sec << " " << ESTIMATED_RTT.tv_nsec << endl;
     
      //CCC << "next_to_recv: " << next_to_recv << endl;
      //CCC << "next_to_send: " << next_to_send << endl;
      //CCC << "next to be acked: " << next_to_be_acked << endl;
     
     
   	//Set the connection state to ESTABLISHED. 
      ctx->connection_state = ESTABLISHED;
   	
   	//Unblock the application.
      stcp_unblock_application(sd);
   
      cout << "CONNECTION ESTABLISHED" <<endl;
      cout << "	next_to_send: " <<next_to_send<<endl;
      cout << "	next_to_recv: " <<next_to_recv<<endl;
      cout << "	next_to_be_acked: " <<next_to_be_acked<<endl;
   	//Enter the control loop.
      control_loop(sd, ctx);
   
   
   
      while (packetsReceived.size() != 0)
      {
         free(packetsReceived[0].data); //WATCH FOR THIS
         packetsReceived.erase(packetsReceived.begin());
      }
               
      while (packetsInFlight.size() != 0)
      {
         free(packetsInFlight[0].data); //WATCH FOR THIS
         packetsInFlight.erase(packetsInFlight.begin());
      }
      
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
      //CCC << "Random sequence number generated: " << ctx->initial_sequence_num << endl;
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
      	
         cout << ESTIMATED_RTT.tv_sec << " " << ESTIMATED_RTT.tv_nsec << endl;
      	
         cout <<"TOP OF CONTROL LOOP" << endl;
         cout << "	in_flight: " << packetsInFlight.size() << endl;
         cout << "	received: " << packetsReceived.size() << endl;
         cout << "	ntba: " << next_to_send << endl;
         cout << "	nts: " << next_to_send << endl;
         cout << "	ntr: " << next_to_recv << endl;
                             
         struct timespec ts;	
      	
         sort (packetsInFlight.begin(), packetsInFlight.end(), compare_expiration);
      	
      	
      	
         if (packetsInFlight.size() > 0)
         {
            ts = get_time();
         	//CCC << "current time: " << ts.tv_sec << " " << ts.tv_nsec << endl;
            ts = packetsInFlight[0].time_expires;
            //CCC << "time_expires: " << ts.tv_sec << " " << ts.tv_nsec << endl;
         }
         else
         {
            ts = get_time();
            ts.tv_sec += 1;
            //CCC << "long_wait" << endl;
         }
      
      	//If our window is full, don't accept any app data
         if (((next_to_be_acked + SENDER_WINDOW) - next_to_send <= 0))
         {
            cout << "		window full" << endl;
            event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED, &ts);
         }
         else 
            event = stcp_wait_for_event(sd, ANY_EVENT, &ts);
      
         //CCC << "doing.." << endl;
      
         if (event == TIMEOUT)
         {
            cout << "			timeout.." << endl;
         	
            //CCC << "Timeout occurred." << endl;
            if (packetsInFlight.size() == 0)
               continue;
            else
            {
               if (packetsInFlight[0].num_sent >= 6)
               {
                  cout << ESTIMATED_RTT.tv_sec << " " << ESTIMATED_RTT.tv_nsec << endl;
                  cout << "Catastrophic network failure; closing connection. 3" << endl;
               	
                  while (packetsReceived.size() != 0)
                  {
                     free(packetsReceived[0].data); //WATCH FOR THIS
                     packetsReceived.erase(packetsReceived.begin());
                  }
               
                  while (packetsInFlight.size() != 0)
                  {
                     free(packetsInFlight[0].data); //WATCH FOR THIS
                     packetsInFlight.erase(packetsInFlight.begin());
                  }
               
               	
                  return;
               }
               else
               {
                  //CCC << "Retransmitting.." << endl;
                  resend_all_packets(sd);
               }
            }
         }
      
         //CCC << ts.tv_sec << endl;
      
      
      	// check whether event was the network, app, or a close request
         if (event & APP_DATA)
         {
            cout << "			APP_DATA"<<endl;
            send_app_data(sd, ctx);
         }
         
         
         if (event & APP_CLOSE_REQUESTED)
         {
            if (ctx->connection_state == ESTABLISHED)
            {
               send_fin_packet(sd, ctx);
               ctx->connection_state = FIN_WAIT_1;
            }
            if (ctx->connection_state == CLOSE_WAIT)
            {
               send_fin_packet(sd, ctx);
               ctx->connection_state = LAST_ACK;
            }
         }
         
         if (event & NETWORK_DATA)
         {
            cout << "			NET_DATA"<<endl;
         	//sleep(1);
            handle_net_data(sd, ctx);
         }
      	
         if (ctx->done)
         {
            cout << "DONE" << endl;
            while (packetsReceived.size() != 0)
            {
               free(packetsReceived[0].data); //WATCH FOR THIS
               packetsReceived.erase(packetsReceived.begin());
            }
         	
            while (packetsInFlight.size() != 0)
            {
               free(packetsInFlight[0].data); //WATCH FOR THIS
               packetsInFlight.erase(packetsInFlight.begin());
            }
         }
      	
      /* etc. */
         //CCC << endl << endl << endl;
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
