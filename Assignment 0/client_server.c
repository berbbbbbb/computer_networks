/*Nader Al-Naji
  Simplex-Talk Client*/

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_LINE_SIZE 1024

int main(int argc, char* argv[])
{
  FILE* fp = NULL;
  struct sockaddr_in sin;
  char buf[MAX_LINE_SIZE];
  int s, len;
  unsigned short SERVER_PORT;
  unsigned long SERVER_ADDR;
  
  /*Parse arguments into data structuce*/
  if (argc == 3)
  {
    SERVER_PORT = atoi(argv[1]);
  }
  else if (argc == 4)
  {
    SERVER_PORT = atoi(argv[1]);
    fp = fopen(argv[3], "r");
    if (fp == NULL)
    {
      perror("client: file opening\n");
      exit(1);
    }
  }
  else
  {
    fprintf(stderr, "usage: client <serverip> <serverport>\n");
    exit(1);
  }

  /*Build address data structure*/
  sin.sin_family = AF_INET; 
  inet_aton(argv[2], &(sin.sin_addr));
  sin.sin_port = SERVER_PORT;
  
  /*Active open*/
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("client: socket\n");
    close(s);
    exit(1);
  }

  if (connect(s, (struct sockaddr*) &sin, sizeof(sin)) < 0)
  {
    perror("client: connect\n");
    close(s);
    exit(1);
  }

  /*Main loop: get/send lines of text*/
  if (fp == NULL)
    fp = stdin;
  while(fgets(buf, sizeof(buf), fp))
  {
    buf[MAX_LINE_SIZE - 1] = '\0';
    len = strlen(buf) + 1;
    send(s, buf, len, 0);
  }
}
