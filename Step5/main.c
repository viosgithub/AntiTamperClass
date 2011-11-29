#include<stdio.h>
#include<getopt.h>

#define HASH 1
#define SALT 2
#define ITERATION_COUNT 3
#define USE_FILE 4

#define SHA1 1
#define SHA256 2
#define SHA512 3


int main(int argc,char **argv)
{
    int opt,num=0,verbose=0;
    int file_pass_flag = 0;
    
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

                //if((optarg is true path)) file_pass_flag = 1;
                break;
        }
    }

    printf("Please input a password\n");

}
