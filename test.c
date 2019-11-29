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
  if(((*ptr)!=0)&&strncmp(ptr,"bsdk",4)==0){
    return 2;
  }
  return 0;
}

void protocol(char *ptr){
  if(check(ptr)>1){
    printf("%d",1);
  }else{
    printf("%d",2);
  }

  if(check1(ptr)==2){
    printf("%d",1);
  }else{
    printf("%d",2);
  }
}

int main(int ac, char **av){

  FILE *fp;
  char str[100];
  char* filename = "./input";
  fp=fopen(filename,"r");
  /* fclose(fp); */
  /* fgets(str,10,fp); */
  /* printf("%s", str); */

  protocol(str);
  return 0;
}
