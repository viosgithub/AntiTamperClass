#include<stdio.h>
#include<getopt.h>

#define HASH 1
#define SALT 2
#define ITERATION_COUNT 3
#define USE_FILE 4

#define SHA1 1
#define SHA256 2
#define SHA512 3

int check_password(char *password)
{
    char c;
    int i=0;
    while(1)
    {
       c = *(password+i) ;
       if(c == '\n')
       {
           c = '\0';
           *(password+i) = '\0';
       }
       else if(c == '\r')
       {
           c = '\0';
           *(password+i) = '\0';
       }
       i++;
       printf("%c[%d]\n",c,(int)c); //for debug
       if((c > 0 && c < 45 && c != 10) || c == 47) 
       {
           printf("\nInvalid password is rejected!\n");
           return -1;
       }
       if(c >= 58 && c < 65)
       {
           printf("\nInvalid password is rejected!\n");
           return -1;
       }
       if(c >= 91 && c < 97)
       {
           printf("\nInvalid password is rejected!\n");
           return -1;
       }
       if(c > 122)
       {
           printf("\nInvalid password is rejected!\n");
           return -1;
       }
       if (c == '\0') break;
       if(i > 20)
       {
           printf("\nInvalid password is rejected!\n");
           return -1;
       }
    }
}

int main(int argc,char **argv)
{
    int opt,num=0,verbose=0;
    int file_pass_flag = 0;
    FILE *fp;
    char password[22];

    int result;
    static struct option long_options[] = {
        {"hash",required_argument,NULL,HASH},
        {"s",required_argument,NULL,SALT},
        {"ic",required_argument,NULL,ITERATION_COUNT},
        {"f",required_argument,NULL,USE_FILE},
        {NULL,0,NULL,0},
    };

    while((result = getopt_long_only(argc,argv,"",long_options,NULL)) != -1)
    {
        switch(result)
        {
            case HASH:
                printf("hash type %s\n",optarg);
                break;
            case SALT:
                printf("salt = %d\n",atoi(optarg));
                break;
            case ITERATION_COUNT:
                printf("ic = %d\n",atoi(optarg));
                break;
            case USE_FILE:
                printf("pass_file_path = %s\n",optarg);
                file_pass_flag = 1;
                if((fp=fopen(optarg,"r")) == NULL)
                {
                    printf("file open error\n");
                    exit(-1);
                }
                fgets(password,22,fp);
                    break;
        }
    }

    if(!file_pass_flag)
    {
        printf("Please input a password\n");
        fgets(password,22,stdin);
    }

    check_password(password);

}
