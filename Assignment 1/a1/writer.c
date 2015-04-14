#include <stdio.h>

int main(void)
{
	const char *c = "GET http://www.google.com:80/index.html/ HTTP/1.0\r\nContent-Length:"
               " 80\r\nIf-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\nConnection: close\r\n\r\n";
	FILE* myFile = fopen("hello.txt", "w");
	fputs(c, myFile);
	return 0;
}