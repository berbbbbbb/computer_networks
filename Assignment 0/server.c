/*Nader Al-Naji
  Simplex-Talk Server*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define MAX_LINE_SIZE 1024
#define MAX_PENDING 5

   int main(int argc, char* argv[])
   {
      FILE* fp = NULL;
      struct sockaddr_in sin;
      char buf[MAX_LINE_SIZE];
      unsigned int len;
      int s, new_s;
      unsigned short SERVER_PORT;
   
   /*Parse arguments into data structuce*/
      if (argc == 2)
      {
         SERVER_PORT = atoi(argv[1]);
      }
      else if (argc == 3)
      {
         SERVER_PORT = atoi(argv[1]);
         fp = fopen(argv[2], "w");
         if (fp == NULL)
         {
            perror("client: file opening\n");
            exit(1);
         }
      }
      else
      {
         fprintf(stderr, "usage: server <serverport> [filename]\n");
         exit(1);
      }
   
   /*Build address data structure*/
      sin.sin_family = AF_INET; 
      sin.sin_addr.s_addr = INADDR_ANY;
      sin.sin_port = htons(SERVER_PORT);
   
   /*Active open*/
      if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      {
         perror("server: socket\n");
         exit(1);
      }
   
      if (bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0)
      {
         perror("server: bind\n");
         exit(1);
      }
      listen(s, MAX_PENDING);
   
   /*Wait for connection then receive and print text.*/
      while(1)
      {
         if ((new_s = accept(s, (struct sockaddr*) &sin, &len)) < 0)
         {
            perror("server: accept");
            exit(1);
         }
         if (fp == NULL)
            fp = stdout;
         while(len = recv(new_s, buf, sizeof(buf), 0))
         {
            fputs(buf, fp);
            fflush(fp);
            if (len < 0)
            {
               close(new_s);
               close(s);
               perror("server: send\n");
               exit(1);
            }
         }
         close(new_s);
      }
   }
