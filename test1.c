#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8080 

int check(char *ptr)
{
  if((*ptr!=0)&&strncmp(ptr,"1234455",7)==0){
    return 2;
  }
  return 0;
}

int check1(char *ptr)
{
  if(((*ptr)!=0)&&strncmp(ptr,"bsdk",4)==0){
    return 2;
  }
  return 0;
}

void protocol(char *ptr){
  if(check(ptr)==2){
    printf("%d",1);
  }else{
    printf("%d",2);
  }
}

int main(int argc, char const *argv[]) 
{ 
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    char *hello = "Hello from server"; 
    char buf[100];
    FILE* f=fmemopen(buf,10,"w");
    int fd=fileno(f);
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        return 0;
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        return 0;
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        return 0;
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        return 0;
    } 
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        return 0;
    } 

    valread = read( new_socket , buffer, 7); 

    protocol(buffer);

    printf("%s\n",buffer); 
    send(new_socket , hello , strlen(hello) , 0 ); 
    printf("Hello message sent\n"); 
    return 0; 
} 
