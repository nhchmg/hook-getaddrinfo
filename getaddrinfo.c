#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <cstdlib>

using namespace std;
//使用环境变量DNS_HOSTS_FILE可以指定hosts文件的位置
//使用环境变量DNS_GET_IP可以指定.sh文件的位置
#define HOSTS1 "/data/data/com.termux/files/usr/etc/hosts"
#define HOSTS2 "./hosts"

// 原始的 getaddrinfo 函数指针
static int (*real_getaddrinfo)(const char *node, const char *service,
                               const struct addrinfo *hints,
                               struct addrinfo **res) = NULL;

bool isIpv4(string szIp)
{
  return -1 != szIp.find('.');
}

bool isIpv6(string szIp)
{
  return -1 != szIp.find(':');
}

string execCmd(const char* cmd)
{
    string result;
    char buffer[128] = {0};
    FILE* pipe = popen(cmd,"r");
    if(pipe)
    {
      try{
         while(!feof(pipe))
         {
           if(fgets(buffer,sizeof(buffer),pipe) != NULL)
           {
              result += buffer;
           }
         }
      }
      catch(...)
      {
      }
      pclose(pipe);
    }
    return result;
}

// 从hosts文件中查找域名对应的IP地址
int find_ip_in_hosts(const char *hostname, char *ip, size_t ip_len) {
    FILE *hosts_file;
    char line[256], *token, *ip_address;

    if(NULL == hostname)
    {
      return 0;
    }

    const char* path = getenv("DNS_HOSTS_FILE");
    const char* hosts_path = NULL == path?HOSTS1:path;
    
    //fprintf(stderr, "hosts_path is = %s\n", hosts_path);
    hosts_file = fopen(hosts_path, "r");
    if (hosts_file) {
      while (fgets(line, sizeof(line), hosts_file)) {
        token = strtok(line, " \t");
        ip_address = token;
        token = strtok(NULL, " \t\n");

        while (token) {
            if (strcmp(token, hostname) == 0) {
                strncpy(ip, ip_address, ip_len);
                fclose(hosts_file);
                return 1;  // 找到匹配
            }
            token = strtok(NULL, " \t\n");
        }
      }

      fclose(hosts_file);
    }

    const char* dnsgetip = getenv("DNS_GET_IP");
    if(NULL != dnsgetip)
    {
       string szCmd = dnsgetip;
       szCmd += " ";
       szCmd += hostname;
       string szIp = execCmd(szCmd.c_str());
       //fprintf(stderr,"szIp=%s\n",szIp.c_str());
       if(!szIp.empty())
       {
         strncpy(ip, szIp.c_str(), ip_len);
         return 1;
       }
    }
    return 0;  // 未找到匹配
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    //fprintf(stderr, "node=%s,service=%s,hints=%p\n",node,service,hints);
    char ipstr[INET6_ADDRSTRLEN] = {0};

    if (!real_getaddrinfo) {
        real_getaddrinfo = (typeof(real_getaddrinfo))dlsym(RTLD_NEXT, "getaddrinfo");
        if (!real_getaddrinfo) {
            //fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
            return EAI_SYSTEM;
        }
    }

    if (find_ip_in_hosts(node, ipstr, sizeof(ipstr))) 
    {
        if(isIpv4(ipstr))
        {
		do
		{
			if( (NULL != hints) && (AF_UNSPEC != hints->ai_family && AF_INET != hints->ai_family) )
		        {
		               break;
		        }
			struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
			struct sockaddr_in *addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));

			if (!ai || !addr) {
			    free(ai);
			    free(addr);
			    return EAI_MEMORY;
			}

			ai->ai_addr = (struct sockaddr *)addr;
			ai->ai_addrlen = sizeof(struct sockaddr_in);
			ai->ai_canonname = NULL;
			ai->ai_next = NULL;
		 
			//fprintf(stderr, "hints->ai_family = %d\n",hints->ai_family);

			ai->ai_family = AF_INET;  // 默认使用IPv4
			if(NULL == hints)
			{
			     ai->ai_flags = 0;
			     ai->ai_socktype = SOCK_STREAM; // 默认使用流套接字
			     ai->ai_protocol = IPPROTO_TCP; // 默认使用TCP协议
			}
			else
			{
			     ai->ai_flags = hints->ai_flags;
			     ai->ai_socktype = hints->ai_socktype;
			     ai->ai_protocol = hints->ai_protocol;
			     //ai->ai_family = hints->ai_family;
			}
			
			const char *protocol;
		       if (hints && hints->ai_protocol == IPPROTO_UDP) {
			    	protocol = "udp";
		        } else {
			    	protocol = "tcp";  // 默认为 TCP
	    		}
			if (service) {
			    struct servent *sv = getservbyname(service, protocol);
			    addr->sin_port = sv ? sv->s_port : htons(atoi(service));
			} else {
			    addr->sin_port = htons(0);  // 没有提供服务名时使用0
			}
			 
			addr->sin_family = ai->ai_family;
			//fprintf(stderr,"ipstr=\"%s\"\n",ipstr);
			addr->sin_addr.s_addr = inet_addr(ipstr);
			
			//fprintf(stderr, "return ai->ai_family = %d,ai->ai_socktype = %d,ai->ai_protocol=%d,addr->sin_port=%d\n",ai->ai_family,ai->ai_socktype,ai->ai_protocol,ntohs(addr->sin_port));
			*res = ai;
			return 0;
		}while(false);
        }
        else if(isIpv6(ipstr))
        {
            do
            {
		    if( (NULL != hints) && (AF_UNSPEC != hints->ai_family && AF_INET6 != hints->ai_family) )
                    {
                       break;
                    }
                     
		    //ipv6
		     struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
		    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)calloc(1, sizeof(struct sockaddr_in6));

		    if (!ai || !addr) {
			free(ai);
			free(addr);
			return EAI_MEMORY;
		    }

		    ai->ai_addr = (struct sockaddr *)addr;
		    ai->ai_addrlen = sizeof(struct sockaddr_in6);
		    ai->ai_canonname = NULL;
		    ai->ai_next = NULL;



		    ai->ai_family = AF_INET6;  // IPv6

		    if (NULL == hints) {
			    ai->ai_flags = 0;
			    ai->ai_socktype = SOCK_STREAM;
			    ai->ai_protocol = IPPROTO_TCP;
		    } else {
			    ai->ai_flags = hints->ai_flags;
			    ai->ai_socktype = hints->ai_socktype;
			    ai->ai_protocol = hints->ai_protocol;
		    }
		    
                    const char *protocol;
		    if (hints && hints->ai_protocol == IPPROTO_UDP) {
		    	protocol = "udp";
                    } else {
		    	protocol = "tcp";  // 默认为 TCP
    		    }
		    if (service) {
			struct servent *sv = getservbyname(service, protocol);
			addr->sin6_port = sv ? sv->s_port : htons(atoi(service));
		    } else {
			addr->sin6_port = htons(0);  // No service provided, use 0
		    }

	            addr->sin6_flowinfo = 0;
		    addr->sin6_scope_id = 0;
		    addr->sin6_family = AF_INET6;
		    if (inet_pton(AF_INET6, ipstr, &addr->sin6_addr) <= 0) {
			free(ai);
			free(addr);
			return EAI_NONAME;  // The IP address was not parsed correctly
		    }

		    *res = ai;
		    return 0;
            }while(false);
        }
    }

    return real_getaddrinfo(node, service, hints, res);
}
