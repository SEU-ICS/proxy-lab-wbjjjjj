#include <stdio.h>
#include "csapp.h"

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *conn_hdr = "Connection: close\r\n";
static const char *proxy_conn_hdr = "Proxy-Connection: close\r\n";

typedef struct cache_block
{
    char uri[MAXLINE];
    char object[MAX_OBJECT_SIZE];
    int size;
    int lru;
    struct cache_block *next; // 链表，指向下一个缓存块
} block;

typedef struct 
{
    block *head;
    int total_size;
    int readcnt;               // 当前读者数量
    sem_t mutex;               // 控制readcnt信号量
    sem_t w;                   // 写锁
} web_cache;
web_cache cache;
int lru_counter = 0;

void sigpipe_handler(int signal);
void doit(int fd);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
void parse_uri(char *uri, char *host, char *path, char *port, char *request_head);
void *thread(void *vargp);
void init_cache(web_cache *cache);
block *read_cache(web_cache *cache, char *uri);
void write_cache(web_cache *cache, char *uri, char *buf, int size);
int get_lru_counter() { return ++lru_counter; }
void evict_one_block(web_cache *cache);
void read_requesthdrs(rio_t *client_rp, int fd);

/* 与tiny.c相同 */
int main(int argc, char **argv) 
{
    setvbuf(stdout, NULL, _IONBF, 0);

    int listenfd, *connfd;
    char hostname[MAXLINE], port[MAXLINE];
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    /* Check command line args */
    if (argc != 2) {
	    fprintf(stderr, "usage: %s <port>\n", argv[0]);
	    exit(1);
    }

    /* 处理 SIGPIPE 信号 */
    Signal(SIGPIPE, sigpipe_handler);

    init_cache(&cache);
    listenfd = Open_listenfd(argv[1]);
    while (1) {
	    clientlen = sizeof(clientaddr);
        connfd = Malloc(sizeof(int));
        printf("Waiting for connection on port %s...\n", argv[1]);
        *connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen); //line:netp:tiny:accept
        printf("Connection accepted, fd=%d\n", *connfd);
        Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, port, MAXLINE, 0);
        printf("Accepted connection from (%s, %s)\n", hostname, port);
	    
        Pthread_create(&tid, NULL, thread, connfd);
    }
}

void init_cache(web_cache *cache)
{
    cache->head = NULL;
    cache->total_size = 0;
    cache->readcnt = 0;
    Sem_init(&cache->mutex, 0, 1);
    Sem_init(&cache->w, 0, 1);
}

block *read_cache(web_cache *cache, char *uri)
{
    block *p = NULL;

    //normalize_uri(uri);

    P(&cache->mutex);
    cache->readcnt++;
    if (cache->readcnt == 1)
        P(&cache->w);
    V(&cache->mutex);

    /* 查找缓存 */
    for (p = cache->head; p; p = p->next) 
    {
        if ((!strcmp(p->uri, uri)) || (uri[strlen(uri)-1] == '/' && strncmp(uri, p->uri, strlen(uri)-1) == 0)) 
        {
            p->lru = get_lru_counter(); // 更新时间戳
            break;
        }
    }

    P(&cache->mutex);
    cache->readcnt--;
    if (cache->readcnt == 0)
        V(&cache->w);
    V(&cache->mutex);

    return p;
}

void write_cache(web_cache *cache, char *uri, char *buf, int size)
{
    if (size > MAX_OBJECT_SIZE)
        return;

    //normalize_uri(uri);

    P(&cache->w);  // 独占写

    // 空间不足，LRU删去块
    while (cache->total_size + size > MAX_CACHE_SIZE)
        evict_one_block(cache);

    // 插入新块
    block *new_block = malloc(sizeof(block));
    strcpy(new_block->uri, uri);
    memcpy(new_block->object, buf, size);
    new_block->size = size;
    new_block->lru = get_lru_counter();

    new_block->next = cache->head;
    cache->head = new_block;
    cache->total_size += size;

    V(&cache->w);

    printf("[CACHE STORE] uri=%s size=%d\n", uri, size);
}

void evict_one_block(web_cache *cache) 
{
    block *prev = NULL, *cur = cache->head;
    block *evict_prev = NULL, *evict = NULL;

    if (!cur) return;

    int min_lru = cur->lru;
    evict = cur;

    // 遍历链表，找到 LRU 最小的块
    while (cur) {
        if (cur->lru < min_lru) {
            min_lru = cur->lru;
            evict_prev = prev;
            evict = cur;
        }
        prev = cur;
        cur = cur->next;
    }

    // 从链表中移除 evict
    if (evict_prev)
        evict_prev->next = evict->next;
    else
        cache->head = evict->next;

    cache->total_size -= evict->size;
    free(evict);
}

void *thread(void *vargp) 
{
    int connfd = *((int *)vargp);
    Pthread_detach(pthread_self());   // 要求的分离模式运行
    Free(vargp);

    doit(connfd);
    Close(connfd);
    return NULL;
}

void sigpipe_handler(int signal)
{
    printf("SIGPIPE caught\n");
    return;
}

/* 与tiny.c前面相似，后面改为转发请求至远程服务器 */
void doit(int fd) 
{
    /* 照搬tiny.c */
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char host[MAXLINE], path[MAXLINE], port[MAXLINE], new_request[MAXLINE];
    rio_t rio, server_rio;

    /* Read request line and headers */
    Rio_readinitb(&rio, fd);
    if (!Rio_readlineb(&rio, buf, MAXLINE))
        return;
    printf("%s", buf);
    sscanf(buf, "%s %s %s", method, uri, version);
    if (strcasecmp(method, "GET")) 
    {                     
        clienterror(fd, method, "501", "Not Implemented",
                    "Proxy does not implement this method");
        return;
    }                                                    

    /* 先查看缓存 */
    block *cache_block = read_cache(&cache, uri);
    if (cache_block)
    {
        printf("cache hit\n");
        // printf("cache block uri: %s\n", cache_block->uri);
        // printf("cache block object: %s\n", cache_block->object);
        // printf("cache block size: %d\n", cache_block->size);
        Rio_writen(fd, cache_block->object, cache_block->size);
        return;
    }

    /* 解析uri */
    parse_uri(uri, host, path, port, new_request);
    // printf("[DEBUG] Forwarding request: host=%s port=%s path=%s\n", host, port, path);

    /* 连接到服务器并发送请求 */
    int serverfd = Open_clientfd(host, port);
    Rio_writen(serverfd, new_request, strlen(new_request));
    read_requesthdrs(&rio,serverfd);

    /* 读取服务器响应并转发给客户端 */
    Rio_readinitb(&server_rio, serverfd);
    char object_buf[MAX_OBJECT_SIZE];
    int object_size = 0;
    size_t n = 0;
    while ((n = Rio_readlineb(&server_rio, buf, MAXLINE)) != 0) 
    {
        object_size += n;
        if (object_size < MAX_OBJECT_SIZE)
        {
            strcat(object_buf, buf);
        }
        Rio_writen(fd, buf, n);
    }
    
    Close(serverfd);
    
    if (object_size <= MAX_OBJECT_SIZE)
    {
        write_cache(&cache, uri, object_buf, object_size);
    }
}

void read_requesthdrs(rio_t *client_rp, int fd)
{
    char buf[MAXLINE];

    // 要求的固定头
    sprintf(buf, "%s", user_agent_hdr);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "%s", conn_hdr);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "%s", proxy_conn_hdr);
    Rio_writen(fd, buf, strlen(buf));

    while (Rio_readlineb(client_rp, buf, MAXLINE) > 0) {
        if (strcmp(buf, "\r\n") == 0)
            break;

        // 跳过已经写过的头
        if (strncmp(buf, "Host:", 5) == 0 ||
            strncmp(buf, "User-Agent:", 11) == 0 ||
            strncmp(buf, "Connection:", 11) == 0 ||
            strncmp(buf, "Proxy-Connection:", 17) == 0)
            continue;

        // 转发剩余头部
        Rio_writen(fd, buf, strlen(buf));
    }

    Rio_writen(fd, "\r\n", 2);
}


/* 照搬tiny.c */
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) 
{
    char buf[MAXLINE];

    /* Print the HTTP response headers */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n\r\n");
    Rio_writen(fd, buf, strlen(buf));

    /* Print the HTTP response body */
    sprintf(buf, "<html><title>Tiny Error</title>");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<body bgcolor=""ffffff"">\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "%s: %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<p>%s: %s\r\n", longmsg, cause);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<hr><em>The Tiny Web server</em>\r\n");
    Rio_writen(fd, buf, strlen(buf));
}

void parse_uri(char *uri, char *host, char *path, char *port, char *new_request) 
{
    // 默认80端口
    strcpy(port, "80");

    char *uri_end = uri + strlen(uri); // uri 的末尾
    char *host_start = strstr(uri, "//");

    // 跳过 "//"
    host_start = (host_start != NULL) ? host_start + 2 : uri;

    // 找host结束位置
    char *host_end = host_start;
    while (*host_end != '/' && *host_end != ':' && *host_end != '\0') host_end++;

    strncpy(host, host_start, host_end - host_start);
    host[host_end - host_start] = '\0';

    char *port_start = NULL;
    char *path_start = NULL;

    if (*host_end == ':') // uri中包含端口号
    {
        port_start = host_end + 1;
        char *port_end = strchr(port_start, '/');
        if (!port_end) port_end = uri_end;
        strncpy(port, port_start, port_end - port_start);
        port[port_end - port_start] = '\0';

        path_start = port_end; 
    } 
    else 
    {
        path_start = host_end;
    }

    strncpy(path, path_start, uri_end - path_start);
    path[uri_end - path_start] = '\0';

    // 新请求行
    sprintf(new_request, "GET %s HTTP/1.0\r\nHost: %s\r\n", path, host);
}