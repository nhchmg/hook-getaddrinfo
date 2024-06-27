# hook-getaddrinfo
termux hook getaddrinfo



g++ -shared -fPIC -o getaddrinfo.so getaddrinfo.c -ldl


//使用环境变量DNS_HOSTS_FILE可以指定hosts文件的位置
//使用环境变量DNS_GET_IP可以指定.sh文件的位置
