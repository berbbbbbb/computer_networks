/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <stdio.h>
#include <assert.h>
#include <iostream>
#include <stdio.h>
#include <math.h>
#include <queue>
#include <string.h>
   using namespace std;

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_dumper.h"
#include "sha1.h"
#include "vnscommand.h"

#define MAX_CACHE_SIZE 100
#define TIMEOUT_VALUE 25

//Helper Methods.
	
	//Method for handling single packets (without a queue)
   static void sr_handle_single_packet(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);	
   
	//Logs a list of packets.
   static void sr_log_pack(char* , struct packetDenied*);
   
	//Check if the packet is an ARP packet.
   static int isArpRequest(uint8_t *);
   static int isArpResponse(uint8_t*);
 	
	//Check if the packet is an IP packet.  
	static int isIPPacket(uint8_t *);
	
	//Check if the packet is an ICMP echo packet.
	static int isICMPEcho(uint8_t *);
	
	//Check if the packet is addressed to the router.
	static int addressedToRouter(uint8_t *, struct sr_if*);
   
	//Get an interface MAC address given an interface IP.
   static struct sr_if* interfaceIpToMac(char*, 
   		struct sr_if*, uint8_t *);
   		
	//Generate an ARP response.
   static uint8_t * generateArpResponse(uint8_t *, struct sr_if*,
   											unsigned int);
   											
	//Generate an ARP response
   static uint8_t * generateArpRequest(int, sr_if*);
	
   //Generate various ICMP responses.
   static uint8_t * generateEchoResponse(uint8_t *, 
   										unsigned int);
   static uint8_t * generateTTLExceeded(uint8_t *, 
   										unsigned int);
   static uint8_t * generatePortUnreachable(uint8_t *, 
   										unsigned int);
   static uint8_t * generateHostUnreachable(uint8_t *, 
   										unsigned int);  					
   															
	//Prepare a packet for forwarding.
   static void fixForForward(uint8_t*, unsigned int, int, sr_if*);
   
	//Fix ICMP/IP checksums.
   static void fixICMPChecksum(uint8_t *, unsigned int);
   static void fixIPChecksum(uint8_t *, unsigned int);
   
	//Given an ARP packet, cache the IP-MAC mapping.
   static void cacheFromArp(uint8_t*);
   
	//Check to see if the address in an IP packet is in the rt.
   static int addressInRoutingTable(uint8_t*);
   
	//Check to see if the MAC address is in the ARP cache.
   static int hasMacAddress(int);
   
	//Print everything in the ARP cache.
	//static void printArpCache();
	
	//Unblock the signal referenced by sig.
   static void unblock(int sig);
	//Make handler the handler for signals of type sig.
   static void setSignalHandler(int sig, void (*handler)(int));
	//The SIGALRM handler.
   static void handleAlarm(int iSig);


//Variables.
	//Array of routing table entries.
   static sr_rt* EntryArray[MAX_CACHE_SIZE];
   //Array of MAC addresses; corresponds to routing table array.
   static uint8_t MacAddrArray[MAX_CACHE_SIZE][6];
   
	//Queue of arp times (for guaranteed timeouts)
   static queue<time_t> arpTimes;
   //Queue of mac addresses in arp cache (maps to MacAddrArray)
   static queue<int> arpIndices;
   //Number of entries in routing table.
   static int currentSize;
   
	//Queue data structures (for outstanding ARPS)
   static queue<sr_instance*> srs;
   static queue<uint8_t *> packets;
   static queue<unsigned int> lengths;
   static queue<char*> interfaces;
   static queue<int> arpTrials;
	
	//Firewall option (initialized in sr_main.c)
   extern int firewall;
	
/*-----------------------------------------------------------------------------
 * Structure: flow
 * Scope: Local
 *
	A unique flow used for firewalling.
 *---------------------------------------------------------------------------*/
	   struct flow
   {
      uint8_t srcIp[4];
      uint8_t dstIp[4];
   	uint8_t proto;
   	uint8_t srcPort[2];
   	uint8_t dstPort[2];
   	time_t timeInserted;
   	
   	int compare(flow f)
   	{
   		for (int i = 0; i < 4; i++)
   		{
   			if ((srcIp[i] != f.srcIp[i]) 
   			||  (dstIp[i] != f.dstIp[i]))
   				return 1;
   		}
   		for (int i = 0; i < 2; i++)
   		{
   			if ((srcPort[i] != f.srcPort[i]) 
   			||  (dstPort[i] != f.dstPort[i]))
   				return 1;
   		}
   		if (proto != f.proto)
   			return 1;
   		
   		return 0;
   	}
   };
	
/*-----------------------------------------------------------------------------
 * Structure: packetDenied
 * Scope: Local
 *
	Linked list of packets denied due to firewall settings to print out.
 *---------------------------------------------------------------------------*/
   struct packetDenied
   {
      uint8_t* pack;
      int packlen;
      packetDenied* next;
   };
	
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

   void sr_init(struct sr_instance* sr) 
   {
   	//Let the user know if the firewall is activated.
      if (firewall)
         cout <<endl << "The firewall is activated." << endl<<endl;
      else
         cout << endl << "The firewall is NOT activated." << endl<<endl;
   
    /* REQUIRES */
      assert(sr);
   	
   	//Zero out the routing table array.
      bzero(EntryArray, MAX_CACHE_SIZE);
   	
   	//Zero out the ARP cache array.
      for (int i = 0; i < MAX_CACHE_SIZE; i++)
         bzero(MacAddrArray[i], 6);
      
   	//Populate the routing table array from the sr_rt* struct.
   	//Values in ARP cache array are zero ==> no MAC address yet.
      sr_rt* rTableEntry = sr->routing_table; 
      currentSize = 0; 
      while (rTableEntry != NULL)
      {
         EntryArray[currentSize] = rTableEntry;
      	
         currentSize++;
         rTableEntry = rTableEntry->next;
      }
   	
   	//Print out IP-MAC mapping (should all be zero).
      //printArpCache();
   	
   	//Make sure SIGINT signals are not blocked.
      unblock(SIGALRM);
   	
   	//Install handlerAlarm as the alarm signal handler.
      setSignalHandler(SIGALRM, handleAlarm);
   	
   } /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 	This method first tries to handle all packets currently queued using
	sr_handle_single_packet and then tries handling the packet it was
	originally asked to handle.
 *---------------------------------------------------------------------*/
   void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
   {			
   	//Print the length of the packet received.
      cout << "Received packet of length: " << len << endl;
      
      //Get a pointer to the first element in the interface list
      sr_if* if_list = sr->if_list;
      
   	//Make copies of the parameters to enqueue safely.
      sr = (sr_instance*)memcpy(malloc(sizeof(*sr)), sr, sizeof(*sr));
      packet = (uint8_t*)memcpy(malloc(len), packet, len);
      interface = (char*)memcpy(malloc(strlen(interface)+1), 
      								  interface, strlen(interface)+1);
   	
   	
   	//Enqueue packet + parameters.
      srs.push(sr);
      packets.push(packet);
      lengths.push(len);
      interfaces.push(interface);
      arpTrials.push(0);
   	
   	//Slight hack: try sending the packet just received FIRST
   	//doesn't really work with a queue....
      int numPackets = srs.size();
      while(numPackets > 1)
      {
         srs.push(srs.front());
         packets.push(packets.front());
         lengths.push(lengths.front());
         interfaces.push(interfaces.front());
         arpTrials.push(arpTrials.front());
      	
         srs.pop();
         packets.pop();
         lengths.pop();
         interfaces.pop();
         arpTrials.pop();
      	
         numPackets--;
      }
   	
   	//Try sending all the packets in the queue.
      numPackets = srs.size();
      while (numPackets > 0)
      {
      	//If 5 arps have been tried, send a HostUnreach.
         if (arpTrials.front() == 5)
         {
         	//Size of the packet.		
            int size = 70;
         
         	//Inform the user.
            cout << "Host Unreachable.." << endl;
            
         	//Generate the new packet.
            uint8_t * buf = generateHostUnreachable(packets.front(), lengths.front());
         		
         		
         	//Send the packet from the proper interface. 	
            while (if_list != NULL)
            {
               if (strcmp(if_list->name, interfaces.front()) == 0)
                  break;
               if_list = if_list->next;
            }		
         	
         	//Adjust the source IP to be the router IP.		
            buf[29] = if_list->ip >> 24;
            buf[28] = if_list->ip << 8 >> 24;
            buf[27] = if_list->ip <<16 >> 24;
            buf[26] = if_list->ip <<24 >> 24;
         	
         	//Fix the checksums.
            fixIPChecksum(buf, size);
            fixICMPChecksum(buf, size);
         	
         	//Send the packet.
            sr_send_packet(srs.front(), buf, size, interfaces.front());
            free(buf);
         
         	//Dequeue the packet + parameters. 
            free(srs.front());
            free(packets.front());
            free(interfaces.front());
         				
            srs.pop();
            packets.pop();
            lengths.pop();
            interfaces.pop();
            arpTrials.pop();
         }
         else
         {
         	//Get pointers to the front of the queue.
            sr_instance* s = srs.front();
            uint8_t* p = packets.front();
            unsigned int l = lengths.front();
            char* i = interfaces.front();
         	
         	//Pass as parameters to send_single_packet.
            sr_handle_single_packet(s, p, l, i);
         	
         	//Dequeue from the front.
            free(srs.front());
            free(packets.front());
            free(interfaces.front());
         	
            srs.pop();
            packets.pop();
            lengths.pop();
            interfaces.pop();
            arpTrials.pop();
         }
         numPackets--;
      }
   }


/*---------------------------------------------------------------------
 * Method: sr_handle_single_packet(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note 1: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 
 	Note 2: This method is the main packet-handling method for a single
	packet. It is called by the sr_handlepacket.
 *---------------------------------------------------------------------*/

   static void sr_handle_single_packet(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
   {
    	/* REQUIRES */
      assert(sr);
      assert(packet);
      assert(interface);
   	
   	//Used as a return value.
      int ret;
   	
      //printArpCache();  
   
    	//Check if the packet is an ARP request.
      if (isArpRequest(packet))
      {
      	//If an ARP request is seen, cache the mapping.
         cout << "Arping from request." << endl;
         cacheFromArp(packet);
      	
      	//Pointer to first element in interface list for traversal.
         struct sr_if* matchedInterface;
      	
      	//Identify the interface potentially requested.
         matchedInterface = interfaceIpToMac(interface, sr->if_list, packet);
      
      	//If the interface is in the list, compile and send an arp response.
         if (matchedInterface != NULL)
         {	
         	//Generate the arp response.
            uint8_t * buf = generateArpResponse(packet, 
               						matchedInterface, len);
            							
         	//Send the response back to the server.
            sr_send_packet(sr, buf, len, interface);
         
         	//Free the buffer.
            free(buf);
         
            return;
         }
         else
            return;
      }
      
      //Check if the packet is an ARP response packet.
      else if (isArpResponse(packet))
      {	
      	//Cache the mapping.
         cacheFromArp(packet); 
         return;
      }
      
   	//Special behavior if the packet doesn't get through the firewall.
      if (firewall && (strcmp(interface, sr->if_list->name) == 0))
      {		
      	//Start and end of the denied packet list (for logging.)
         static struct packetDenied* end = NULL;
         static struct packetDenied* start = NULL;
      
      	//If this is the first dropped packet..
         if (start == NULL)
         {
         	//Malloc a struct packetDenied.
            start = (struct packetDenied*)malloc(sizeof(struct packetDenied));
         	
         	//Initialize the linked list of packets to print.
            start->packlen = len;
            start->pack = (uint8_t*)malloc(len);
            for (int i = 0; i < (int)len; i++)
               start->pack[i] = packet[i];
            end = start;
            start->next = NULL;
         }
         else
         {
         	//Add the packet to the end of the linked list.
            end->next = (struct packetDenied*)malloc(sizeof(struct packetDenied));
            end = end->next;
         	
            end->pack = (uint8_t*)malloc(len);
            end->packlen = len;
            for (int i = 0; i < (int)len; i++)
               end->pack[i] = packet[i];
            end->next = NULL;
         }
         //Notify the user of a silently dropped packet.
         cout << "Dropping incoming packet-- addressed to internal." <<endl;
         
      	//Log all dropped packets.
         sr_log_pack("dropped.log", start);
      }
      
      //If the packet is an IP packet
      else if (isIPPacket(packet))
      {
      	//If the packet is addressed to the router.
         if (addressedToRouter(packet, sr->if_list))
         {
            cout << "Packet addressed to router" << endl;
         	//If the IP packet encapsulates an ICMP echo request packet.
            if (isICMPEcho(packet))
            {
               cout << "ICMP echo request" << endl;
               
            	//Generate an echo response.
               uint8_t * buf = generateEchoResponse(packet, len);
               
            	//Send the response back to the server.
               sr_send_packet(sr, buf, len, interface);
            
               return;
            }
         	
         	//If a UDP or TCP packet is addressed to an interface, 
         	//respond with an ICMP Port Unreachable packet.
            if (packet[23] == 17 || packet[23] == 6)
            {
               int size = 70;
            
            	//Generate a PortUnreach packet.
               cout << "TCP/UDP addressed to interface.." << endl;
               uint8_t * buf = generatePortUnreachable(packet, len);
               
            	
            	//Send the response back to the server.
               sr_send_packet(sr, buf, size, interface);
            	
            	//Free the buffer.
               free(buf);
            	
               return;
            }
         }
         
         //If TTL is zero respond with ICMP TTL exceeded
         else if ((packet[22] == 0) || (packet[22] == 1))
         {
            cout << "ICMP TTL exceeded" << endl;
            int size = 70;
         	
         	//Generate a TTLExceeded message
            uint8_t * buf = generateTTLExceeded(packet, len);
         	
         	//Send from the proper interface.
            sr_if* if_list = sr->if_list;
            	
            while (if_list != NULL)
            {
               if (strcmp(if_list->name, interface) == 0)
                  break;
               if_list = if_list->next;
            }	
            //Modify the source IP			
            buf[29] = if_list->ip >> 24;
            buf[28] = if_list->ip << 8 >> 24;
            buf[27] = if_list->ip <<16 >> 24;
            buf[26] = if_list->ip <<24 >> 24;
         	
         	//Fix the checksums.
            fixIPChecksum(buf, size);
            fixICMPChecksum(buf, size);
         	
            //Send the response back to the server.
            sr_send_packet(sr, buf, size, interface);
            
         	//Free the buffer.
            free(buf);
         	
            return;
         }	
         
         //If the packet is addressed to an IP in the routing table
         else
         { 
         	//Get the index of the IP in the EntryArray.
            ret = addressInRoutingTable(packet);
         	
            if (ret == -1)
            {
               for (int i = 0; i < currentSize; i++)
                  if (((EntryArray[i]->dest.s_addr) & (EntryArray[i]->mask.s_addr)) == 0)
                     ret = i;
            }
            
            if (ret < 0)
               return;
         		
         	
         	//If we have the MAC address in our ARP cache,
         	//Send the packet right along.
            if (hasMacAddress(ret))
            {
            	//Decrement the TTL.
               packet[22]--;
            	
            	//Get the proper interface.
               sr_if* if_list = sr->if_list;
            	
               while (if_list != NULL)
               {
                  if (strcmp(if_list->name, EntryArray[ret]->interface) == 0)
                     break;
                  if_list = if_list->next;
               }
            
            	//Prepare the packet for forwarding.
               fixForForward(packet, len, ret, if_list);
            	
            	//Send the packet.
               sr_send_packet(sr, packet, len, if_list->name);
               return;
            }
            //If we don't, do an ARP request on the proper interface. 
            else
            {
               cout << "Sending an ARP request." << endl;
            
            	//Make a copy of the queue elements 
               sr = (sr_instance*)memcpy(malloc(sizeof(*sr)), sr, sizeof(*sr));
               packet = (uint8_t*)memcpy(malloc(len), packet, len);
               interface = (char*)memcpy(malloc(strlen(interface)+1), 
               								  interface, strlen(interface)+1);
            
            	//Enqueue the elements for resubmission later.
               srs.push(sr);
               packets.push(packet);
               lengths.push(len);
               interfaces.push(interface);
               arpTrials.push(arpTrials.front() + 1);
             	
            	//Find the proper interface.
               sr_if* if_list = sr->if_list;
            	
               while (if_list != NULL)
               {
                  if (strcmp(if_list->name, EntryArray[ret]->interface) == 0)
                     break;
                  if_list = if_list->next;
               }
            
            	//Generate an ARP request packet
               uint8_t * buf = generateArpRequest(ret, if_list);
            	
            	//Send the request packet along to the desired server.
               sr_send_packet(sr, buf, 42, if_list->name);
            
            	//Free the buffer.
               free(buf);
            
               return;
            }				
         }
      }  
   	
   }/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: isArpRequest
 * Scope: Local
 
 	Return true (1) if the packet is an arp request, false (0) otherwise.
 *---------------------------------------------------------------------*/
   static int isArpRequest(uint8_t * packet)
   {
   //Check the "type" field of the ethernet header for 0806 (imples arp)
      if ((packet[12] == 0x8) && (packet[13] == 0x6) 
      &&  (packet[21] == 0x1))
         return 1;
      else
         return 0;
   }
/*--------------------------------------------------------------------- 
 * Method: isArpResponse
 * Scope: Local
 
 	Return true (1) if the packet is an arp response, false (0) otherwise.
 *---------------------------------------------------------------------*/
   static int isArpResponse(uint8_t * packet)
   {
   //Check the "type" field of the ethernet header for 0806 (imples arp)
      if ((packet[12] == 0x8) && (packet[13] == 0x6) 
      &&  (packet[21] == 0x2))
         return 1;
      else
         return 0;
   }
   
   static int isArpResponse(uint8_t* packet);
/*--------------------------------------------------------------------- 
 * Method: interfaceIpToMac
 * Scope: Local
 
 	Loop through interfaces to determine if the arp request can be
	answered by the router. Return the interface
	with the corresponding ip if the ip maps to one of the router's
	interfaces. NULL otherwise.
 *---------------------------------------------------------------------*/

   static struct sr_if* interfaceIpToMac(char* ingressInterface, 
   		struct sr_if* if_list, uint8_t * packet)
   {
   //Iterate over interfaces to find the one 
   //in the request's collision domain.
      while (if_list != NULL)
      {
         if (strcmp(if_list->name, ingressInterface) == 0)
         {
         //Get the arp request's ip.
            uint32_t destIp = 0;			
            for (int i = 0; i < 4; i++)
               destIp += packet[i+38]*(pow(16,2*i));
         
         //Compare it to the interface's ip
         //Return the interface if it's a match.
            if (destIp == if_list->ip)
               return if_list;
            //If the ip isn't a match, return NULL.
            else
               return NULL;
         }
      //Move to the next interface.
         if_list = if_list->next;
      }
   //If none of the interface IP's match, return NULL.
      return NULL;
   }
	
/*--------------------------------------------------------------------- 
 * Method: generateArpRequest
 * Scope: Local
 
 	Compile an arp request for the entry at position index in the 
	routing table.
 *---------------------------------------------------------------------*/
   static uint8_t * generateArpRequest(int index, sr_if* if_list)
   {
   //Create an empty buffer that will hold the ARP request.
      uint8_t* buf = (uint8_t*)malloc(42);
      bzero(buf, 42);
   
   //Put in the destination MAC address (router interface mac).
      for (int i = 0; i < 6; i++)
         buf[i] = 0xff;
         
   //Put in the source MAC address (broadcast).
      for (int i = 6; i < 12; i++)
         buf[i] = if_list->addr[i-6];	    
      //Ethernet frame type (806 = ARP)
      buf[12] = 0x08;
      buf[13] = 0x06;
   //ARP hardware type (1 = ethernet)
      buf[14] = 0x00;
      buf[15] = 0x01;
   //ARP protocol type (800 = IPv4)
      buf[16] = 0x08;
      buf[17] = 0x00;
   //ARP hardware length (ethernet --> 6 bytes)
      buf[18] = 0x06;
   //ARP protocol length (IPv4 --> 4 bytes)
      buf[19] = 0x04;
   //ARP operation type (1 --> ARP request)
      buf[20] = 0x00;
      buf[21] = 0x01;
   
   //ARP source MAC address (router interface mac)
      for (int i = 22; i < 28; i++)
         buf[i] = if_list->addr[i-22];
      
      //ARP source IP address (router interface ip)
      buf[31] = if_list->ip >> 24;
      buf[30] = if_list->ip << 8 >> 24;
      buf[29] = if_list->ip <<16 >> 24;
      buf[28] = if_list->ip <<24 >> 24;
      //ARP destination mac (server mac)
      for (int i = 32; i < 38; i++)
         buf[i] = 0xFF;
            
      //ARP destination ip (server ip)
      buf[38] = EntryArray[index]->gw.s_addr <<24 >>24;
      buf[39] = EntryArray[index]->gw.s_addr <<16 >>24;
      buf[40] = EntryArray[index]->gw.s_addr <<8  >>24;
      buf[41] = EntryArray[index]->gw.s_addr >>24;
               
      return buf;
   }

/*--------------------------------------------------------------------- 
 * Method: generateArpResponse
 * Scope: Local
 
 	Compile an arp response packet to send back.
 *---------------------------------------------------------------------*/
   static uint8_t * generateArpResponse(uint8_t * packet, 
   						struct sr_if* matchedInterface, unsigned int len)
   {
   //Create an empty buffer that will hold the ARP response.
      uint8_t* buf = (uint8_t*)malloc(len);
      bzero(buf, len);
   
   //Put in the destination MAC address (server mac).
      for (int i = 0; i < 6; i++)
         buf[i] = packet[i+6];
   //Put in the source MAC address (router interface mac).
      for (int i = 6; i < 12; i++)
         buf[i] = matchedInterface->addr[i-6];
   //Ethernet frame type (806 = ARP)
      buf[12] = 0x08;
      buf[13] = 0x06;
   //ARP hardware type (1 = ethernet)
      buf[14] = 0x00;
      buf[15] = 0x01;
   //ARP protocol type (800 = IPv4)
      buf[16] = 0x08;
      buf[17] = 0x00;
   //ARP hardware length (ethernet --> 6 bytes)
      buf[18] = 0x06;
   //ARP protocol length (IPv4 --> 4 bytes)
      buf[19] = 0x04;
   //ARP operation type (2 --> ARP response)
      buf[20] = 0x00;
      buf[21] = 0x02;
   
   //ARP source MAC address (router interface mac)
      for (int i = 22; i < 28; i++)
         buf[i] = matchedInterface->addr[i-22];
   
   //ARP source IP address (router interface ip)
      for (int i = 28; i < 32; i++)
         buf[i] = packet[i+10];
   
   //ARP destination mac (server mac)
      for (int i = 32; i < 38; i++)
         buf[i] = packet[i-26];
   	
   //ARP destination ip (server ip)
      for (int i = 38; i < 42; i++)
         buf[i] = packet[i-10];
   
      return buf;
   }
	
	
/*--------------------------------------------------------------------- 
 * Method: isIPPacket
 * Scope: Local
 
 	Return true (1) if the packet is an IP packet, false (0) otherwise.
 *---------------------------------------------------------------------*/
   static int isIPPacket(uint8_t * packet)
   {
   //Check the "type" field of the ethernet header for 0800 (imples IP)
      if ((packet[12] == 0x8) && (packet[13] == 0x0))
         return 1;
      else
         return 0;
   }
   
/*--------------------------------------------------------------------- 
 * Method: addressedToRouter
 * Scope: Local
 
 	Check to see if an IP packet is addressed to the ip of one of the
	router's interfaces.	Return true (1) if it is, false (0) otherwise.
 *---------------------------------------------------------------------*/
   static int addressedToRouter(uint8_t * packet, struct sr_if* if_list)
   {
   	//Get the packet's destination ip.
      uint32_t destIp = 0;			
      for (int i = 0; i < 4; i++)
         destIp += packet[i+30]*(pow(16,2*i));
   
   	//Iterate over interfaces and attempt to find one with a matching IP.
      while (if_list != NULL)
      {
         //Compare dest ip to the interface's ip
         //Return true (1) if it's a match.
         if (destIp == if_list->ip)
            return 1;
      	//Move to the next interface.
         if_list = if_list->next;
      }
   //If none of the interface IP's match, return NULL.
      return 0;
   
   }

/*--------------------------------------------------------------------- 
 * Method: isICMPEcho
 * Scope: Local
 
 	Return true (1) if the packet is an ICMP echo request packet, 
	false (0) otherwise.
 *---------------------------------------------------------------------*/
   static int isICMPEcho(uint8_t * packet)
   {
   //Check the "type" field of the ethernet header for 0800 (imples IP)
      if ((packet[23] == 0x1) && (packet[34] == 0x8))
         return 1;
      else
         return 0;
   }
	
/*--------------------------------------------------------------------- 
 * Method: generateEchoResponse
 * Scope: Local
 
 	Compile an ICMP echo response packet to send back.
 *---------------------------------------------------------------------*/
   static uint8_t * generateEchoResponse(uint8_t * packet, 
   										unsigned int len)
   {
   	//fixICMPChecksum(packet, len);
      uint8_t swapper;
   	//Swap source and destination mac addresses.
      for (int i = 0; i < 6; i++)
      {
         swapper = packet[i];
         packet[i] = packet[i+6];
         packet[i+6] = swapper;
      }
   	
   	//Swap source and destination IP addresses.
      for (int i = 0; i < 4; i++)
      {
         swapper = packet[i+26];
         packet[i+26] = packet[i+30];
         packet[i+30] = swapper;
      }
   	
   	//Set ICMP type to reply.
      packet[14+(packet[14] & 0xF)*4] = 0;
   	
   	//Fix the checksums.
      fixICMPChecksum(packet, len);
      fixIPChecksum(packet, len);
      return packet;
   }
	
/*--------------------------------------------------------------------- 
 * Method: generateTTLExceeded
 * Scope: Local
 
 	Compile an ICMP TTL exceeded packet to send back.
 *---------------------------------------------------------------------*/
   static uint8_t * generateTTLExceeded(uint8_t * packet, 
   										unsigned int len)
   {
   	//Set the packet size.
      int size = 70;
   
   	//Allocate memory for a buffer.
      uint8_t* buf = (uint8_t*)malloc(size);
      bzero(buf, size);
   
        //Enter source and destination mac addresses.                             
      for (int i = 0; i < 6; i++)
      {
         buf[i] = packet[i+6];
         buf[i+6] = packet[i];
      }
   
        //Enter ethernet frame type.                                              
      buf[12] = 0x08;
      buf[13] = 0x00;
   
        //Enter version(4) and header length(5).                                  
      buf[14] = 0x45;
   
        //Enter packet length (111).                                              
      buf[16] = 0x00;
      buf[17] = size-14;
   
        //Fragments                                                               
      buf[18] = packet[18];
      buf[19] = packet[19];
   
   	//Flags/fragment offset.                                                  
      buf[20] = 0x0;
      buf[21] = 0x0;
   
        //New TTL.                                                                
      buf[22] = 0x32;
   
        //Protocol = 1 (ICMP)                                                     
      buf[23] = 0x01;
   
        //Set header checksum to 0.                                               
      buf[24] = 0;
      buf[25] = 0;
   
        //Enter source and destination IP addresses.                              
      for (int i = 0; i < 4; i++)
      {
         buf[26+i] = packet[30+i];
         buf[30+i] = packet[26+i];
      }
   
        //Set ICMP type to TTL exceeded.                                          
      buf[34] = 11;
   
        //Set code to 0.                                                          
      buf[35] = 0;
   
        //Set checksum to 0.                                                      
      buf[36] = 0;
      buf[37] = 0;
   
        //Unused chunks.                                                          
      for (int i = 0; i < 4; i++)
         buf[38+i] = 0;
   
      fixIPChecksum(packet, len);
   
        //Fill the rest with the IP header + 64B of packet.                       
      for (int i = 14; i < (int)len && (i+28) < size ; i++)
         buf[i+28] = packet[i];
   
      for (int i = len; (i+28) < size; i++)
         buf[i+28] = 0;
   
   	//Fix the checksums.
      fixIPChecksum(buf, size);
      fixICMPChecksum(buf, size);
      
      return buf;
   }
	
/*--------------------------------------------------------------------- 
 * Method: generatePortUnreachable
 * Scope: Local
 
 	Compile an ICMP Port Unreachable response for when a TCP/UDP packet
	is addressed to a router interface.
 *---------------------------------------------------------------------*/
   static uint8_t * generatePortUnreachable(uint8_t * packet, 
   										unsigned int len)
   {
   	//Set the packet size.
      int size = 70;
   
   	//Allocating memory for a buffer.
      uint8_t* buf = (uint8_t*)malloc(size);
      bzero(buf, size);
   	
   	//Enter source and destination mac addresses.
      for (int i = 0; i < 6; i++)
      {
         buf[i] = packet[i+6];
         buf[i+6] = packet[i];
      }
   	
   	//Enter ethernet frame type.
      buf[12] = 0x08;
      buf[13] = 0x00;
   	
   	//Enter version(4) and header length(5).
      buf[14] = 0x45;
   	
   	//Enter packet length (111).
      buf[16] = 0x00;
      buf[17] = size-14;
   	
   	//Fragments
      buf[18] = packet[18]; 
      buf[19] = packet[19];
   	
   	//Flags/fragment offset.
      buf[20] = 0x0;
      buf[21] = 0x0;
   	
   	//New TTL.
      buf[22] = 0x32;
   	
   	//Protocol = 1 (ICMP)
      buf[23] = 0x01;
   	
   	//Set header checksum to 0.
      buf[24] = 0;
      buf[25] = 0;
   	
   	//Enter source and destination IP addresses.
      for (int i = 0; i < 4; i++)
      {
         buf[26+i] = packet[30+i];
         buf[30+i] = packet[26+i];
      }
   	
   	//Set ICMP type to Unreachable Message.
      buf[34] = 3;
   	
   	//Set code to 3 (port unreachable).
      buf[35] = 3;
   	
   	//Set checksum to 0.
      buf[36] = 0;
      buf[37] = 0;
   	
   	//Unused chunks.
      for (int i = 0; i < 4; i++)
         buf[38+i] = 0;
   	
      fixIPChecksum(packet, len);
      
   	//Fill the rest with the IP header + 64B of packet.
      for (int i = 14; i < (int)len && (i+28) < size; i++)
         buf[i+28] = packet[i];
   	
      for (int i = len; (i+28) < size; i++)
         buf[i+28] = 0;  	
   	
   	//Fix the checksums.
      fixIPChecksum(buf, size);
      fixICMPChecksum(buf, size);
      
      return buf;
   }
	
	
/*--------------------------------------------------------------------- 
 * Method: generateHostUnreachable
 * Scope: Local
 
 	Compile an ICMP Host Unreachable response for when a TCP/UDP packet
	is addressed to a router interface.
 *---------------------------------------------------------------------*/
   static uint8_t * generateHostUnreachable(uint8_t * packet, 
   										unsigned int len)
   {
   	//Set the packet size.
      int size = 70;
   
   	//Allocate memory for the buffer.
      uint8_t* buf = (uint8_t*)malloc(size);
      bzero(buf, size);
   	
   	//Enter source and destination mac addresses.
      for (int i = 0; i < 6; i++)
      {
         buf[i] = packet[i+6];
         buf[i+6] = packet[i];
      }
   	
   	//Enter ethernet frame type.
      buf[12] = 0x08;
      buf[13] = 0x00;
   	
   	//Enter version(4) and header length(5).
      buf[14] = 0x45;
   	
   	//Enter packet length (111).
      buf[16] = 0x00;
      buf[17] = size-14;
   	
   	//Fragments
      buf[18] = packet[18]; 
      buf[19] = packet[19];
   	
   	//Flags/fragment offset.
      buf[20] = 0x0;
      buf[21] = 0x0;
   	
   	//New TTL.
      buf[22] = 0x32;
   	
   	//Protocol = 1 (ICMP)
      buf[23] = 0x01;
   	
   	//Set header checksum to 0.
      buf[24] = 0;
      buf[25] = 0;
   	
   	//Enter source and destination IP addresses.
      for (int i = 0; i < 4; i++)
      {
         buf[26+i] = packet[30+i];
         buf[30+i] = packet[26+i];
      }
   	
   	//Set ICMP type to Unreachable Message.
      buf[34] = 3;
   	
   	//Set code to 3 (port unreachable).
      buf[35] = 1;
   	
   	//Set checksum to 0.
      buf[36] = 0;
      buf[37] = 0;
   	
   	//Unused chunks.
      for (int i = 0; i < 4; i++)
         buf[38+i] = 0;
   	
      fixIPChecksum(packet, len);
      
   	//Fill the rest with the IP header + 64B of packet.
      for (int i = 14; i < (int)len && (i+28) < size; i++)
         buf[i+28] = packet[i];
   	
      for (int i = len; (i+28) < size; i++)
         buf[i+28] = 0;  	
   	
   	//Fix the checksums.
      fixIPChecksum(buf, size);
      fixICMPChecksum(buf, size);
      
      return buf;
   }

	
/*--------------------------------------------------------------------- 
 * Method: fixICMPChecksum
 * Scope: Local
 
 	Recalculate the ICMP checksum for a packet and change the field's
	value.
 *---------------------------------------------------------------------*/
   static void fixICMPChecksum(uint8_t * packet, unsigned int len)
   {		
   	//Get the start of the ICMP packet.
      int startOfICMP = 14+(packet[14] & 0xF)*4;
   
   	//Set the checksum to zero.
      packet[startOfICMP+2] = 0x0;
      packet[startOfICMP+3] = 0x0;
   	
   	//Checksum algorithm.
      register u_long checksum = 0;				
   	
      for (int i = startOfICMP; i < (int)len; i += 2)
      {
         checksum += packet[i]*256+packet[i+1];
         if (checksum & 0xFFFF0000)
         {
         	//Carry occurred-- wrap around.
            checksum &= 0xFFFF;
            checksum++;
         }
      }
   	
   	//Set the checksum in the packet.
      packet[startOfICMP+2] = (((u_short)(~(checksum & 0xFFFF)))&(0xFF00))>>8;
      packet[startOfICMP+3] = (((u_short)(~(checksum & 0xFFFF)))&(0xFF));
   }
	
	
/*--------------------------------------------------------------------- 
 * Method: fixIPChecksum
 * Scope: Local
 
 	Recalculate the IP checksum for a packet and change the field's
	value.
 *---------------------------------------------------------------------*/
   static void fixIPChecksum(uint8_t * packet, unsigned int len)
   {
   	//Set the IP checksum to zero.
      packet[24] = 0x0;
      packet[25] = 0x0;
   	
   	//Checksum algorithm.
      register u_long checksum = 0;				
   	
      for (int i = 14; i < 13+(packet[14] & 0xF)*4; i+= 2)
      {
         checksum += packet[i]*256+packet[i+1];
         if (checksum & 0xFFFF0000)
         {
         	//Carry occurred-- wrap around.
            checksum &= 0xFFFF;
            checksum++;
         }
      }
   	
   	//Set the checksum.
      packet[24] = (((u_short)(~(checksum & 0xFFFF)))&(0xFF00))>>8;
      packet[25] = (((u_short)(~(checksum & 0xFFFF)))&(0xFF));
   }
	
/*--------------------------------------------------------------------- 
 * Method: fixForForward
 * Scope: Local
 
 	Modify the packet to make it ready to send to the next hop.
 *---------------------------------------------------------------------*/
   static void fixForForward(uint8_t* packet, unsigned int len, 
   								  int ret, sr_if* if_list)
   {
      assert (if_list != NULL);
   	
   	//Modify source mac to be router interface mac.
      for (int i = 0; i < 6; i++)
         packet[i] = MacAddrArray[ret][i];	
   	
   	//Modify dest mac to be mac of next hop.
      for (int i = 6; i < 12; i++)
         packet[i] = if_list->addr[i-6];
   
   	//Recompute Checksum
      fixIPChecksum(packet, len);
   }

/*--------------------------------------------------------------------- 
 * Method: cacheFromArp
 * Scope: Local
 
 	Cache the IP-Mac address mapping from an arp request or response.
 *---------------------------------------------------------------------*/
   static void cacheFromArp(uint8_t* packet)
   {
   	//Get the packet's source ip.
      uint32_t srcIp = 0;			
      for (int i = 0; i < 4; i++)
         srcIp += packet[i+28]*(pow(16,2*i));
         
      for (int i = 0; i < currentSize; i++)
      {
         if (EntryArray[i]->gw.s_addr == srcIp)
         {
         	//Cache the IP -> MAC Address mapping.
            for (int j = 0; j < 6; j++)
            {
               MacAddrArray[i][j] = packet[j+22];
            }
         	//Note the time last arped and set an alarm.
            int hasValue = 0;
            for (int j = 0; j < (int)arpIndices.size(); j++)
            {
               int temp = arpIndices.front();
               if (temp == i)
                  hasValue = 1;
               arpIndices.push(temp);
               arpIndices.pop();
            }
            if (!hasValue)
            {
               if (arpTimes.empty())
                  alarm(TIMEOUT_VALUE);
               arpTimes.push(time(NULL));
               arpIndices.push(i);
            }
            
            cout << "Adding ARP information to cache. " << endl;
            return;
         }
      }  
   }
	
/*--------------------------------------------------------------------- 
 * Method: printArpCache
 * Scope: Local
 
 	Print out the values in the EntryArray and the MacAddrArray.
 *---------------------------------------------------------------------*/
 /*  static void printArpCache()
   {
      for (int i = 0; i < currentSize; i++)
      {
         sr_print_routing_entry(EntryArray[i]);
         cout << "Mac address: ";
         for (int j = 0; j < 5; j++)
            printf("%x::", MacAddrArray[i][j]);
         printf("%x\n", MacAddrArray[i][5]);
      	
      }
   }
*/	
/*--------------------------------------------------------------------- 
 * Method: addressInRoutingTable
 * Scope: Local
 
 	Check to see if the IP packet's destination address currently
	has an entry in the routing table. Return the index of the entry 
	if it's in the routing table, -1 otherwise.
 *---------------------------------------------------------------------*/	
   static int addressInRoutingTable(uint8_t* packet)
   {
   	//Get the packet's destination ip.
      uint32_t destIp = 0;			
      for (int i = 0; i < 4; i++)
         destIp += packet[i+30]*(pow(16,2*i));
   	
   	//Compare the IP to the IP's in the routing table.
      for (int i = 0; i < currentSize; i++)
      {
         if (((EntryArray[i]->dest.s_addr) 
         	& (EntryArray[i]->mask.s_addr)) == destIp)
            return i;
      }   
      return -1;
   }
	
/*--------------------------------------------------------------------- 
 * Method: hasMacAddress
 * Scope: Local
 
 	Check to see if the routing table entry associated with index has
	a MAC address associated with it. If it does, return 1 else return 0.
	
	Note: A mac address with a value of all zeroes is used to represent
	the lack of a mac address in the MacAddrArray array.
 *---------------------------------------------------------------------*/
   static int hasMacAddress(int index)
   {
      assert(index < currentSize);
   	
   	//Check to see if MAC address is in ARP cache.
      for (int i = 0; i < 6; i++)
         if (MacAddrArray[index][i] != 0)
            return 1;
   			
      return 0;
   }
   
/*--------------------------------------------------------------------- 
 * Method: unblock
 * Scope: Local
 
 	Unblock the signal referenced by sig. 
 *---------------------------------------------------------------------*/
   static void unblock(int sig)
   {
      sigset_t sSet;
      int iRet;
   
      sigemptyset(&sSet);
      sigaddset(&sSet, sig);
      iRet = sigprocmask(SIG_UNBLOCK, &sSet, NULL);
      if (iRet != 0)
      {
         perror("sr");
         exit(1);
      }
   }
 
 /*--------------------------------------------------------------------- 
 * Method: setSignalHandler
 * Scope: Local
 
 	Make handler the handler for signals of type sig.
 *---------------------------------------------------------------------*/
   static void setSignalHandler(int sig, void (*handler)(int))
   {
      void (*pfRet)(int);
   
      pfRet = signal(sig, handler);
      if (pfRet == SIG_ERR)
      {
         perror("sr");
         exit(EXIT_FAILURE);
      }
   }
 
 /*--------------------------------------------------------------------- 
 * Method: handleAlarm
 * Scope: Local
 
 	Delete the entry in MacAddrArray that has timed out.
 *---------------------------------------------------------------------*/
   static void handleAlarm(int iSig)
   {
      assert(!arpTimes.empty());
   
   	//Zero out the MAC address.
      for (int i = 0; i < 6; i++)
         MacAddrArray[arpIndices.front()][i] = 0;
   
   	//Pop the times off the queue
      time_t lastTime = arpTimes.front();
      arpTimes.pop();
      arpIndices.pop();
   
   	//If the queue is empty
      if (!arpTimes.empty())
      {
      	//Reset the alarm to the proper time.
         if ((unsigned int)(difftime(arpTimes.front(),lastTime)) == 0)
            alarm(TIMEOUT_VALUE);
         else
            alarm((unsigned int)(difftime(arpTimes.front(),lastTime)));
      }	
   }

/*-----------------------------------------------------------------------------
 * Method: sr_log_pack()
 * Scope: Local
 *
 	Log all the packets in a linked list of packets.
 *---------------------------------------------------------------------------*/

   void sr_log_pack(char* log, struct packetDenied* start)
   {
   	//Open a file to log.
      FILE* logfile = sr_dump_open(log,0,start->packlen);
   
      if(!logfile)
      {
         return; }
   
   	//Iterate over all the packets in the list.
      while (start != NULL)
      {
         struct pcap_pkthdr h;
         int size;
      
         size = min(PACKET_DUMP_SIZE, start->packlen);
      
         gettimeofday(&h.ts, 0);
         h.caplen = size;
         h.len = (size < PACKET_DUMP_SIZE) ? size : PACKET_DUMP_SIZE;
      
         sr_dump(logfile, &h, start->pack);
         fflush(logfile);
      
      	//Advance the start pointer.
			
         start = start->next;
      }
   } /* -- sr_log_packet -- */