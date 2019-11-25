#include <stdio.h>
#include<string.h>
#include <stdlib.h>


char *serial = "\x31\x3e\x3d\x26\x31";

int check(char *ptr)
{
  if((*ptr!=0)&&strcmp(ptr,"asd")==0){
    return 2;
  }
  return 0;
}

int check1(char *ptr)
{
  if(((*ptr+3)!=0)&&strncmp(ptr+3,"asdk",4)==0){
    return 2;
  }
  return 0;
}

int main(int ac, char **av){

  /* if(check(av[1])>1){ */
  /*   printf("%d",1); */
  /* }else{ */
  /*   printf("%d",2); */
  /* } */

  if(check1(av[1])==2){
    printf("%d",1);
  }else{
    printf("%d",2);
  }

  return 0;
}
