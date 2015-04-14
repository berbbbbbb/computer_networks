#include "proxy_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>


#define MAX_PENDING 100	//Maximum number of pending connections (backlog)
#define PORT argv[1]	//Alias for port
#define MAX_LINE_SIZE 1024 //Read buffer size
#define MAX_CONNECTIONS 500 //Maximum number of concurrent connections
#define MAX_SIZE 16000 //Maximum request size

   static int numChildren = 0;


//Kill zombies.
   void sigchld_handler(int s)
   {
      numChildren--;
      while (waitpid(-1, NULL, WNOHANG) > 0);
   }

//Send reliably.
   int sendall(int s, char* buf, int* len)
   {
      int total = 0;
      int bytesleft = *len;
      int n = 0;
   
   	/*Keep sending until everything is gone.*/
      while (total < *len)
      {
         n = send(s, buf + total, bytesleft, 0);
         
         if (n == -1)
            break;
         total += n;
         bytesleft -= n;
      }
   	
      *len = total;
   
   	/*Return -1 on failure.*/
      if (n == -1)
         return n;
      else
         return 0;
   }


   int main(int argc, char* argv[])
   {
      int s, new_s;			//Sockets.
      struct addrinfo hints, *list, *p;	//Address structures.
      struct sockaddr_storage their_addr;	//Client address structure.
      socklen_t sin_size;	//Size of client address structure.
      struct sigaction sa;	//Used for killing zombies.
      char buf[MAX_LINE_SIZE];	//Read buffer.
      int retval;		//Return value.
      pid_t pid;
   
   //Zero out the structure.
      memset(&hints, 0, sizeof hints);
   
   //Fill it with information.
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE;
   
	  if (argc != 2)
		  printf("Usage: proxy PORT\n You can configure your web browser to use this proxy.\n");
	   
   //Create a list of potential addresses.
      retval = getaddrinfo(NULL, PORT, &hints, &list);
      if (retval != 0)
      {
         fprintf(stderr, "Fail on getaddrinfo.");
         return 1;
      }	
   //Bind to first available address.
      for (p = list; p != NULL; p = p->ai_next)
      {
         if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
         {
            perror("Fail on creating socket.");
            continue;
         }
         if (bind(s, p->ai_addr, p->ai_addrlen) == -1)
         {
            close(s);
            perror("Fail on binding.");
            continue;
         }
      
         break;
      }
      if (p == NULL)
      {
         fprintf(stderr, "Could not bind socket.");
         return 1;
      }
   
   //Free the address list (don't need it anymore)
      freeaddrinfo(list);
   
   //Listen on the socket.
      if (listen(s, MAX_PENDING) == -1)
      {
         perror("Fail on listening.");
         return 1;
      }
   	
   //Set up the zombie handler.
      sa.sa_handler = sigchld_handler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = SA_RESTART;
      if (sigaction(SIGCHLD, &sa, NULL) == -1)
      {
         perror("Fail on sigaction.");
         return 1;
      }
   
   //Enter main loop.
      while(1)
      {
      	//Fork a child process if under the MAX_CONNECTION limit.
         if (numChildren < MAX_CONNECTIONS)
         {
         //Accept available connection.
            sin_size = sizeof their_addr;
            new_s = accept(s, (struct sockaddr*) &their_addr, &sin_size);
            if (new_s == -1)
            {
               perror("Error on accept.");
               continue;
            }
         
            pid = fork();
            if (pid == -1)
            {
               memset(buf, 0, sizeof buf);
               strcpy(buf, "HTTP:/1.0 500 Internal Server Error\r\nContent-Length: "
                        		"0\r\nConnection: close\r\n\r\n");
               int len = strlen(buf);
               sendall(new_s, buf, &len);
               return 1;
            }
            //In the child process.
            else if (pid == 0) 
            {
               char* request = (char *)malloc(MAX_LINE_SIZE);
               int currentSize = MAX_LINE_SIZE;
               int n = 1;
               int pos = 0;
               struct ParsedRequest* req = ParsedRequest_create();
            
            //Close listening socket.
               close(s);
            
            //Read in the request.
               int max_size = 0;
               memset(buf, 0, sizeof buf);
               while (1)
               {
                  n = recv(new_s, buf, sizeof buf - 1, 0);
                  if (n < 0) 
                  {
                     memset(buf, 0, sizeof buf);
                     strcpy(buf, "HTTP:/1.0 500 Internal Server Error\r\nContent-Length: "
                        		"0\r\nConnection: close\r\n\r\n");
                     int len = strlen(buf);
                     sendall(new_s, buf, &len);
                     exit(1);	
                  }
                  //Expand the request buffer if it's *almost* full.
                  if (n + pos > (currentSize - 3))
                  {
                     currentSize = currentSize*2;
                     request = (char *)realloc(request, currentSize);
                  }
                  
               	//Append the read buffer to the request buffer.
                  request[pos] = '\0';
                  strcat(request, buf);
               
               	//Prepare for next iteration.
                  pos = pos + n;
                  memset(buf, 0, sizeof buf);
                  
                  if (max_size > MAX_SIZE)
                  {
                     memset(buf, 0, sizeof buf);
                     strcpy(buf, "HTTP:/1.0 414 URI Too Long\r\nContent-Length: "
                        		"0\r\nConnection: close\r\n\r\n");
                     int len = strlen(buf);
                     sendall(new_s, buf, &len);
                     exit(1);	
                  }
                  max_size += n;
               	//If the double CRLF is found, break out of the loop.
                  if (strcmp(request + pos - 4, "\r\n\r\n") == 0)
                     break;
                  else if ((strcmp(request + pos - 3, "\r\n\r") == 0)
                  ||  (strcmp(request + pos - 3, "\r\n\n") == 0))
                  {
                     request[pos - 3] = '\0';
                     strcat(request, "\r\n\r\n"); 
                     break;
                  }
                  else if(strcmp(request + pos - 4, "\r\n\r\r") == 0)
                  {
                     request[pos - 1] = '\n';
                     break;
                  }
               }	
             	//Get the length of the request.  
               int len = strlen(request); 
               
            	//Make sure the method is get-- send an error back otherwise.
               if ((strncmp(request, "PATH", 4) == 0)
               ||	(strncmp(request, "HEAD", 4) == 0)
               || (strncmp(request, "PUT", 3) == 0)
               || (strncmp(request, "POST", 4) == 0)
               || (strncmp(request, "DELETE", 6) == 0)
               || (strncmp(request, "TRACE", 5) == 0)
               || (strncmp(request, "OPTIONS", 7) == 0)
               || (strncmp(request, "CONNECT", 7) == 0))
               {
                  memset(buf, 0, sizeof buf);
                  strcpy(buf, "HTTP:/1.0 501 Not Implemented\r\nContent-Length: "
                     			"0\r\nConnection: close\r\n\r\n");
                  len = strlen(buf);
                  sendall(new_s, buf, &len);
                  exit(1);				
               }
            	
            	//Feed the request into the Parsed_Request data structure.
               if (ParsedRequest_parse(req, request, len) < 0) {
                  memset(buf, 0, sizeof buf);
                  strcpy(buf, "HTTP:/1.0 400 Bad Request\r\nContent-Length: "
                     			"0\r\nConnection: close\r\n\r\n");
                  len = strlen(buf);
                  sendall(new_s, buf, &len);
                  exit(1);		
               }	
               if (req->port == NULL)
                  req->port = "80";
            
            	//Zero out the request buffer to enter properly parsed
            	//information.
               memset(request, 0, currentSize);
            	
            	//Fill in the request buffer.
               strcat(request, req->method);
               strcat(request, " ");
               strcat(request, req->path);
               strcat(request, " ");
               strcat(request, "HTTP/1.0\r\n");
               strcat(request, "Host: ");
               strcat(request, req->host);
               //Set the port if necessary.
               if (strcmp(req->port, "80") != 0)
               {
                  strcat(request, ":");
                  strcat(request, req->port);
               }
               strcat(request, "\r\n");						
            
               size_t i = 0;
               struct ParsedHeader* tmp;
               while(req->headersused > i)
               {
                  tmp = req->headers + i;
                  if (strcmp(tmp->key, "Connection")
                  &&  strcmp(tmp->key, "Keep-Alive")
                  &&  strcmp(tmp->key, "Host"))
                  {          
                     strcat(request, tmp->key);
                     strcat(request, ": ");
                     strcat(request, tmp->value);
                     strcat(request, "\r\n");
                  }
                  i++;
               }
               strcat(request, "Connection: close\r\n\r\n");
            
					printf("%s\n", request);
				
            //Connect to desired host.
            
            //Zero out the structure.
               memset(&hints, 0, sizeof hints);
            //Get host information.
               hints.ai_family = AF_UNSPEC;
               hints.ai_socktype = SOCK_STREAM;
            
            //Create a list of potential addresses.
               retval = getaddrinfo(req->host, req->port, &hints, &list);
            
               if (retval != 0)
               {
                  memset(buf, 0, sizeof buf);
                  strcpy(buf, "HTTP:/1.0 500 Internal Server Error\r\nContent-Length: "
                        		"0\r\nConnection: close\r\n\r\n");
                  len = strlen(buf);
                  sendall(new_s, buf, &len);
                  exit(1);	
               }	
               
            // Loop through all the results and connect to the first host we can.
               for(p = list; p != NULL; p = p->ai_next) 
               {
                  if ((s = socket(p->ai_family, p->ai_socktype,
                  p->ai_protocol)) == -1) 
                     continue;
               
                  if (connect(s, p->ai_addr, p->ai_addrlen) == -1) 
                  {
                     close(s);
                     continue;
                  }
                  
                  break;
               }
               if (p == NULL)
               {
                  memset(buf, 0, sizeof buf);
                  strcpy(buf, "HTTP:/1.0 500 Internal Server Error\r\nContent-Length: "
                        		"0\r\nConnection: close\r\n\r\n");
                  len = strlen(buf);
                  sendall(new_s, buf, &len);
                  exit(1);
               }
            	
            	//Send the request to the host.	
               len = strlen(request);
               sendall(s, request, &len);  
            	  
            	//Forward the response to the client.
               memset(buf, 0, sizeof buf);
               pos = 0;
               while ((n = recv(s, buf, sizeof buf - 1, 0)))
               {
                  sendall(new_s, buf, &n);
                  memset(buf, 0, sizeof buf);
               }
               
            	//Close the connection and exit the child.
               close(new_s);
               exit(0);
            }
            //If still in the parent, close the connection.
            else
            {
            	numChildren++;
               close(new_s);
           	}
         }
         //If we have exceeded the maximum number of connections,
         //wait a second for things to clear up.
         else
            sleep(1);
      }
      return 0; //Should never get here.
   
   }