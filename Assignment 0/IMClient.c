/*Nader Al-Naji
  IM Client*/

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_LINE_SIZE 1024
#define MAX_PENDING 5

   int main(int argc, char* argv[])
   {
      struct sockaddr_in connect_addr, this_addr;
      char buf[MAX_LINE_SIZE];
      int s_client, s_server, new_s, is_connected;
      unsigned int len_server, len_client;
      unsigned short CONNECT_PORT, THIS_PORT;
      unsigned long CONNECT_ADDR;
   
   /*Parse arguments into data structuce*/
      if (argc == 4)
      {
         THIS_PORT = atoi(argv[1]);
         CONNECT_PORT = atoi(argv[3]); 
      }
      else
      {
         fprintf(stderr, "usage: IMClient <hostport> <serverip> <serverport>\n");
         exit(1);
      }
   
   /*Build address data structures*/
      connect_addr.sin_family = AF_INET; 
      inet_aton(argv[2], &(connect_addr.sin_addr));
      connect_addr.sin_port = htons(CONNECT_PORT);
   
      this_addr.sin_family = AF_INET;
      this_addr.sin_addr.s_addr = INADDR_ANY;
      this_addr.sin_port = htons(THIS_PORT);
   
   /*Active open (client)*/
      if ((s_client = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      {
         perror("client: socket\n");
         close(s_client);
         exit(1);
      }
   
   /*Active open (server)*/
      if ((s_server = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      {
         perror("server: socket\n");
         close(s_server);
         exit(1);
      }
   
   /*Connect to outside server.*/
      if ((is_connected = connect(s_client, (struct sockaddr*) &connect_addr,\
				  sizeof(connect_addr))) < 0)
      {
         perror("The server you are trying to contact has not been startd\n");
      }
      else
         printf("Host connected to peer.\n");
   
   
   /*Bind your server*/
      if (bind(s_server, (struct sockaddr*) &this_addr, sizeof(this_addr)) < 0)
      {
         perror("server: bind\n");
         exit(1);
      }
      listen(s_server, MAX_PENDING);
   
   /*Main loop: get/send lines of text*/
      printf("Waiting for peer to contact you.\n");
      if ((new_s = accept(s_server, (struct sockaddr*) &this_addr, &len_server)) < 0)
      {
         perror("server: accept");
         exit(1);
      }
      printf("Peer connected to host.\n");

   /*Try connecting again now that peer server is running.*/
      if(is_connected < 0)
      {
         is_connected = connect(s_client, (struct sockaddr*) &connect_addr,\
				sizeof(connect_addr));
         if (is_connected >= 0)
            printf("Host connected to peer.\n");
      }
   
   
   
   
   
      if(fork() == 0)
      {
         close(s_server);
         printf("you: ");
         fflush(stdout);
         while(1)
         {
         /*If there's a connection, start sending data; if not-- keep trying to \
	   connect until there is one.*/
            if ((is_connected >= 0) && fgets(buf, sizeof(buf), stdin))
            {
               printf("you: ");
               fflush(stdout);
               buf[MAX_LINE_SIZE - 1] = '\0';
               len_client = strlen(buf) + 1;
               send(s_client, buf, len_client, 0);
            }
            else
            {
	       is_connected = connect(s_client, (struct sockaddr*) &connect_addr, \
				     sizeof(connect_addr));
	       sleep(.5);
               continue;
            }
         }
      }
      else
      {
         close(s_client);
         while(1)
         {
            if(len_server = recv(new_s, buf, sizeof(buf), 0))
            {
               printf("\nthem: %syou: ", buf);
               fflush(stdout);
            }
         }
      }
   }
