#include <stdio.h>
#include<string.h>
#include <stdlib.h>



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

int main(int ac, char **av){

  FILE *fp;
  char str[100];
  char* filename = av[1];
  fp=fopen(filename,"r");

  char buf0[100];
  fread(buf0,1,3,fp);
  memcpy(str,buf0,3);
  fread(buf0,1,4,fp);
  memcpy(str+3,buf0,4);

  char buf[100];
  fmemopen(buf,10,"rb");

  printf("%s", str);
  fclose(fp);

  protocol(str);
  return 0;
}
