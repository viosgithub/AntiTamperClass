#include<stdio.h>
#include<getopt.h>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>

#define HASH 1
#define SALT 2
#define ITERATION_COUNT 3
#define USE_FILE 4

#define SHA1 1
#define SHA256 2
#define SHA512 3

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

void kdf(int hashtype,char *password,char *salt,int ic,unsigned char *dkey)
{
	unsigned char result_u[65];
	unsigned char data[65];
	int password_length;
	int result_len;
	EVP_MD *hashfunc;


	password_length = strlen(password);
	strcpy(data,salt);
	strcat(data,"00000001");
#ifdef DEBUG
	printf("in KDF:\n");
	printf("pass=%s,salt=%s,ic=%d\n",password,salt,ic);
	printHashType(hashtype);	
	printf("salt+data=%s\n",data);
#endif
	switch(hashtype)
	{
		case SHA1:
			hashfunc = EVP_sha1();
			break;
		case SHA256:
			hashfunc = EVP_sha256();
			break;
		case SHA512:
			hashfunc = EVP_sha512();
			break;
	}

	int i;
	for(i=0;i<ic;i++)
	{
		if(i == 0)
		{
			HMAC(hashfunc,password,password_length,data,strlen(data),result_u,&result_len);
			strcpy(dkey,result_u);
		}
		else
		{
			HMAC(hashfunc,password,password_length,result_u,result_len,result_u,&result_len);
			strxor(dkey,result_u);

		}
		hexoutput(dkey,result_len);

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
#ifdef DEBUG
		printf("%c[%d]\n",c,(int)c); //for debug
#endif
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
			if(i <= 14)
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
	int iteration_count = 1000;
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
				if(iteration_count < 1000)
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

