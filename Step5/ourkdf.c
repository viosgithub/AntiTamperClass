#include<stdio.h>
#include<getopt.h>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>

#define HASH 1
#define SALT 2
#define ITERATION_COUNT 3
#define USE_FILE 4

#define MIN_IC 1000
#define MIN_PASS 14

#define SHA1 1
#define SHA256 2
#define SHA512 3

#define GOOD_SALT 1
#define TOO_LONG_SALT -1
#define NO_HEX_SALT -2

//#define DEBUG

void antiNewLine(char *str)
{
    int i;
    for(i=0;i<strlen(str);i++)
    {
        if(str[i] == '\n')
        {
            str[i] = '\0';
            return;
        }
    }
}

void hexoutput(const unsigned char *dkey,int length)
{
    int i;
    unsigned char c;

    for(i=0;i<length;i++)
    {
        c = *(dkey+i) & 0xF0;
        c = c >> 4;
        printf("%x",c);
        c = *(dkey+i) & 0x0F;
        printf("%x",c);
    }
    printf("\n");
}

void showdata(char *name,unsigned char *data)
{
    int i;
    printf("data name:%s\n",name);
    printf("string:%s\n",data);
    printf("asciicode\n");
    for(i=0;i<strlen(data);i++)
    {
        printf("%u\n",data[i]);
    }

}

void strxor(unsigned char *s1,unsigned char *s2)
{
    int i;
    for(i=0;i<64;i++)
    {
        *(s1+i) = *(s1+i) ^ *(s2+i);
    }
}

void printHashType(int hashtype)
{
    switch(hashtype)
    {
        case SHA1:
            printf("SHA1\n");
            break;
        case SHA256:
            printf("SHA256\n");
            break;
        case SHA512:
            printf("SHA512\n");
            break;
        default:
            printf("HASH TYPE ERROR\n");
    }
}

unsigned char char2num(unsigned char c)
{
    if(c >= 48 && c <= 57) return (c - 48);
    else if(c >= 97 && c <= 102) c -= 32;
    if(c >= 65 && c <= 70) return (c - 55);
    else 
    {
        return '\0';
    }



}
int isGoodSalt(char *str)
{
    int i;
    register char c;
    if(strlen(str) >= 33) return TOO_LONG_SALT;
    for(i=0;i<strlen(str);i++)
    {
        c = str[i];
        if(c >= 48 && c <= 57) continue;
        else if(c >= 97 && c <= 102) continue;
        else if(c >= 65 && c <= 70) continue;
        else return NO_HEX_SALT;
    }

    return GOOD_SALT;
}
void hex2bin(unsigned char *data,int *length)
{
    int i=0;
    unsigned char now_c,next_c;
    unsigned char hex_data[33];
    unsigned char byte;
    strcpy(hex_data,data);
    strcat(hex_data,"00000001");
    while(1)
    {
        if(hex_data[i*2] == '\0')
        {
            *length = i;
            break;
        }
        else if(hex_data[i*2+1] == '\0')
        {
            now_c = char2num(hex_data[i*2]);
            *length = i+1;
            byte = now_c;
            data[i] = byte;
            break;
        }
        else
        {
            now_c = char2num(hex_data[i*2]);
            next_c = char2num(hex_data[i*2+1]);
            byte = now_c << 4;
            byte += next_c;
            data[i] = byte;
        }
        i++;
    }


}

void kdf(int hashtype,char *password,char *salt,int ic,unsigned char *dkey)
{
    unsigned char result_u[65];
    unsigned char data[33];
    int password_length;
    int result_len;
    int init_data_len;
    EVP_MD *hashfunc;


    password_length = strlen(password);
    strcpy(data,salt);
    hex2bin(data,&init_data_len);
#ifdef DEBUG
    printf("in KDF:\n");
    printf("pass=%s,salt=%s,ic=%u\n",password,salt,ic);
    printHashType(hashtype);	
#endif
    switch(hashtype)
    {
        case SHA1:
            hashfunc = (EVP_MD *)EVP_sha1();
            break;
        case SHA256:
            hashfunc = (EVP_MD *)EVP_sha256();
            break;
        case SHA512:
            hashfunc = (EVP_MD *)EVP_sha512();
            break;
    }

    unsigned int i;
    for(i=0;i<ic;i++)
    {
        if(i == 0)
        {
            HMAC(hashfunc,password,password_length,data,init_data_len,result_u,&result_len);
            memcpy(dkey,result_u,result_len);
        }
        else
        {
            HMAC(hashfunc,password,password_length,result_u,result_len,result_u,&result_len);
            strxor(dkey,result_u);

        }

    }

}

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
        if (c == '\0')
        {
            if(i <= MIN_PASS)
            {
                printf("\nInvalid password is rejected!:too short\n");
                return -1;
            }
            else{
                return 0;
            }
        }
        if(i > 20)
        {
            printf("\nInvalid password is rejected!:too long\n");
            return -1;
        }
    }
}

int main(int argc,char **argv)
{
    int opt;
    unsigned int iteration_count = 1000;
    int file_pass_flag = 0;
    int hashtype = SHA1;
    FILE *fp;
    char password[22];
    char salt[33];
    unsigned char dkey[65];
    int dkey_length = 20;
    int salt_flag = 0;
    int ic_flag = 0;

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
                if(strcmp("sha-1",optarg) == 0)
                {
                    hashtype = SHA1;
                }
                else if(strcmp("sha-256",optarg) == 0)
                {
                    hashtype = SHA256;
                    dkey_length = 32;
                }
                else if(strcmp("sha-512",optarg) == 0)
                {
                    hashtype = SHA512;
                    dkey_length = 64;
                }
                else
                {
                    printf("hash type Error:正しいハッシュタイプを指定してください");
                    exit(-1);
                }

                break;
            case SALT:
                salt_flag = 1;
                strcpy(salt,optarg);
                switch(isGoodSalt(salt))
                {
                    case TOO_LONG_SALT:
                        printf("Error:Salt is too long\n");
                        exit(-1);
                    case NO_HEX_SALT:
                        printf("Error:Salt must be HEX\n");
                        exit(-1);
                }
#ifdef DEBUG
                printf("salt=%s\n",salt);
#endif

                break;
            case ITERATION_COUNT:
                ic_flag = 1;
                iteration_count = atoi(optarg);
#ifdef DEBUG
                printf("ic = %d\n",iteration_count);
#endif
                if(iteration_count < MIN_IC)
                {
                    printf("iteration count must be over 1000\n");
                    exit(-1);
                }
                break;
            case USE_FILE:
#ifdef DEBUG
                printf("pass_file_path = %s\n",optarg);
#endif
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

    if(!salt_flag)
    {
        printf("Please in put a salt\n");
        exit(-1);
    }

    if(!ic_flag)
    {
        printf("Please in put a iteration_count\n");
        exit(-1);
    }

    if(!file_pass_flag)
    {
        printf("Please input a password\n");
        fgets(password,22,stdin);
    }

    if(check_password(password) != 0) exit(-1);
    kdf(hashtype,password,salt,iteration_count,dkey);
    //showdata("dkey",dkey);
    hexoutput(dkey,dkey_length);


}

