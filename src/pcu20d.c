/* PCU20 file server. FreeBSD 13+, C11 and the base system libc only. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define VERSION "1.0.0"
#define MAX_SHARES 32
#define MAX_NETS 64
#define MAX_CLIENTS 128
#define MAX_PORTS 256
#define MAX_ENTRIES 10000
#define FRAME_MAX 65535
#define BODY_MAX (FRAME_MAX-10)
#define WIRE_PATH 260

typedef struct { char name[128], path[PATH_MAX]; int fd; bool ro; unsigned seen; } Share;
typedef struct { uint32_t address, mask; } Network;
typedef struct {
    char host[INET_ADDRSTRLEN], encoding[32], username[256], password[256];
    uint16_t ports[MAX_PORTS]; size_t nports, nshares, nnets;
    Network nets[MAX_NETS]; Share shares[MAX_SHARES];
    int timeout_ms, max_clients, log_level; uint64_t max_file;
    bool compatibility, truncate;
} Config;
typedef struct { Share *share; int parent; char name[NAME_MAX+1]; bool root; } Resolved;
typedef struct { char name[NAME_MAX+1]; uint8_t body[297]; bool directory; } Entry;
typedef struct {
    int sock, file, lock; bool target_valid, created, staged, authenticated, done, lines_sent;
    Resolved target; char stage[64];
    uint32_t block; uint16_t handle;
    Entry *entries; size_t entry_count, entry_next;
    uint8_t linebuf[BODY_MAX]; size_t line_length;
} Session;

static Config cfg;
static volatile sig_atomic_t stopping;

static void logmsg(int level, const char *format, ...) {
    if (level > cfg.log_level) return;
    char stamp[32]; time_t now=time(NULL); struct tm tm;
    localtime_r(&now,&tm); strftime(stamp,sizeof stamp,"%Y-%m-%d %H:%M:%S",&tm);
    fprintf(stderr,"%s %s pid=%ld ",stamp,(const char*[]){"ERROR","WARNING","INFO","DEBUG"}[level],(long)getpid());
    va_list args; va_start(args,format); vfprintf(stderr,format,args); va_end(args); fputc('\n',stderr);
}
static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static uint32_t u32(const uint8_t *p) { return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static void p16(uint8_t *p,uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void p32(uint8_t *p,uint32_t v) { for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8)); }
static int fail(int error) { errno=error; return -1; }
static int copystr(char *out,size_t capacity,const char *in) {
    size_t n=strlen(in); if(n>=capacity)return fail(ENAMETOOLONG); memcpy(out,in,n+1);return 0;
}
static char *trim(char *p) {
    while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n')p++;
    size_t n=strlen(p); while(n&&(p[n-1]==' '||p[n-1]=='\t'||p[n-1]=='\r'||p[n-1]=='\n'))p[--n]=0;
    return p;
}
static int integer(const char *s,uint64_t min,uint64_t max,uint64_t *out) {
    char *end; errno=0; if(*s=='-'||!*s)return -1;
    unsigned long long n=strtoull(s,&end,10);
    if(errno||*end||n<min||n>max)return -1;*out=n;return 0;
}
static int boolean(const char *s,bool *out) {
    if(!strcasecmp(s,"true")||!strcasecmp(s,"yes")||!strcmp(s,"1")||!strcasecmp(s,"on")){*out=true;return 0;}
    if(!strcasecmp(s,"false")||!strcasecmp(s,"no")||!strcmp(s,"0")||!strcasecmp(s,"off")){*out=false;return 0;}
    return -1;
}
static int ports(const char *value) {
    char buffer[4096],*save,*part; cfg.nports=0;
    if(copystr(buffer,sizeof buffer,value))return -1;
    for(part=strtok_r(buffer,",",&save);part;part=strtok_r(NULL,",",&save)) {
        char *dash=strchr(part,'-');uint64_t a,b;
        if(dash)*dash++=0;
        if(integer(trim(part),1,65535,&a))return -1;
        b=a;if(dash&&integer(trim(dash),a,65535,&b))return -1;
        for(uint64_t p=a;p<=b;p++) {
            bool found=false;for(size_t i=0;i<cfg.nports;i++)if(cfg.ports[i]==p)found=true;
            if(!found){if(cfg.nports==MAX_PORTS)return -1;cfg.ports[cfg.nports++]=(uint16_t)p;}
        }
    }
    return cfg.nports?0:-1;
}
static int networks(const char *value) {
    char buffer[4096],*save,*part;cfg.nnets=0;
    if(copystr(buffer,sizeof buffer,value))return -1;
    for(part=strtok_r(buffer,",",&save);part;part=strtok_r(NULL,",",&save)) {
        char *s=trim(part),*slash=strchr(s,'/');uint64_t bits=32;struct in_addr addr;
        if(slash){*slash++=0;if(integer(trim(slash),0,32,&bits))return -1;}
        if(cfg.nnets==MAX_NETS||inet_pton(AF_INET,trim(s),&addr)!=1)return -1;
        uint32_t mask=bits?(UINT32_MAX<<(32-bits)):0;
        cfg.nets[cfg.nnets++]=(Network){ntohl(addr.s_addr)&mask,mask};
    }
    return cfg.nnets?0:-1;
}
static int recode(const char *from,const char *to,const char *in,size_t n,char *out,size_t cap,size_t *used) {
    iconv_t cd=iconv_open(to,from);if(cd==(iconv_t)-1)return -1;
    char *src=(char*)in,*dst=out;size_t left=cap?cap-1:0;
    size_t result=iconv(cd,&src,&n,&dst,&left);int saved=errno;
    iconv_close(cd);errno=saved;
    if(result==(size_t)-1||n||!cap)return -1;
    *dst=0;if(used)*used=(size_t)(dst-out);return 0;
}
static int read_config(const char *filename) {
    memset(&cfg,0,sizeof cfg);cfg.timeout_ms=30000;cfg.max_clients=16;cfg.max_file=67108864;
    cfg.truncate=true;cfg.log_level=2;strcpy(cfg.host,"127.0.0.1");strcpy(cfg.encoding,"CP1252");
    ports("6754");networks("127.0.0.1/32");
    for(size_t i=0;i<MAX_SHARES;i++)cfg.shares[i].fd=-1;
    FILE *f=fopen(filename,"r");if(!f){perror(filename);return -1;}
    char line[8192];int section=-2;unsigned lineno=0;uint64_t server_seen=0;bool server_section=false;int result=-1;
    while(fgets(line,sizeof line,f)) {
        lineno++;if(!strchr(line,'\n')&&!feof(f))goto bad;
        char *s=line;if(lineno==1&&!memcmp(s,"\xef\xbb\xbf",3))s+=3;
        s=trim(s);if(!*s||*s=='#'||*s==';')continue;
        if(*s=='[') {
            size_t n=strlen(s);if(n<3||s[n-1]!=']')goto bad;s[n-1]=0;s=trim(s+1);
            if(!strcmp(s,"server")){if(server_section)goto bad;server_section=true;section=-1;}
            else if(!strncmp(s,"share:",6)) {
                s+=6;if(!*s||strlen(s)>=sizeof cfg.shares[0].name||strpbrk(s,"\\/:*?"))goto bad;
                for(size_t i=0;i<cfg.nshares;i++)if(!strcasecmp(s,cfg.shares[i].name))goto bad;
                if(cfg.nshares==MAX_SHARES)goto bad;section=(int)cfg.nshares++;
                strcpy(cfg.shares[section].name,s);
            } else goto bad;
            continue;
        }
        char *eq=strchr(s,'=');if(!eq||section==-2)goto bad;*eq++=0;char *key=trim(s),*v=trim(eq);
        uint64_t number=0;int rc=-1;
        if(section>=0) {
            Share *sh=&cfg.shares[section];unsigned bit=0;
            if(!strcmp(key,"path")){bit=1;rc=copystr(sh->path,sizeof sh->path,v);}
            else if(!strcmp(key,"read_only")){bit=2;rc=boolean(v,&sh->ro);}
            if(!bit||(sh->seen&bit)||rc)goto bad;sh->seen|=bit;
        } else {
            static const char *keys[]={"listen","ports","allowed_clients","timeout","max_clients","max_file_size","encoding","log_level","auth","username","password","truncate_on_write"};
            size_t k;for(k=0;k<sizeof keys/sizeof keys[0];k++)if(!strcmp(key,keys[k]))break;
            if(k==sizeof keys/sizeof keys[0]||(server_seen&(UINT64_C(1)<<k)))goto bad;
            server_seen|=UINT64_C(1)<<k;
            switch(k) {
            case 0: rc=copystr(cfg.host,sizeof cfg.host,v);break;
            case 1: rc=ports(v);break;
            case 2: rc=networks(v);break;
            case 3: {char *end;errno=0;double seconds=strtod(v,&end);if(!errno&&*v&&!*end&&isfinite(seconds)&&seconds>=0.01&&seconds<=86400){cfg.timeout_ms=(int)(seconds*1000);rc=0;}break;}
            case 4: rc=integer(v,1,MAX_CLIENTS,&number);cfg.max_clients=(int)number;break;
            case 5: rc=integer(v,1,INT64_MAX,&cfg.max_file);break;
            case 6: if(!strcasecmp(v,"cp1252")||!strcasecmp(v,"cp1251")||!strcasecmp(v,"utf-8"))rc=copystr(cfg.encoding,sizeof cfg.encoding,v);break;
            case 7: for(int j=0;j<4;j++)if(!strcasecmp(v,(const char*[]){"ERROR","WARNING","INFO","DEBUG"}[j])){cfg.log_level=j;rc=0;}break;
            case 8: if(!strcmp(v,"credentials")){cfg.compatibility=false;rc=0;}else if(!strcmp(v,"compatibility")){cfg.compatibility=true;rc=0;}break;
            case 9: rc=copystr(cfg.username,sizeof cfg.username,v);break;
            case 10: rc=copystr(cfg.password,sizeof cfg.password,v);break;
            case 11: rc=boolean(v,&cfg.truncate);break;
            }if(rc)goto bad;
        }
    }
    if(ferror(f)||!server_section||!cfg.nshares||(!cfg.compatibility&&(!*cfg.username||!*cfg.password)))goto bad;
    struct in_addr addr;if(inet_pton(AF_INET,cfg.host,&addr)!=1)goto bad;
    for(size_t i=0;i<cfg.nshares;i++) {
        Share *sh=&cfg.shares[i];char canonical[PATH_MAX];
        if(!(sh->seen&1)||sh->path[0]!='/'||!realpath(sh->path,canonical))goto bad;
        if(copystr(sh->path,sizeof sh->path,canonical))goto bad;
        sh->fd=open(sh->path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(sh->fd<0)goto bad;
    }
    char temp[512];size_t n;
    if(recode("UTF-8",cfg.encoding,cfg.username,strlen(cfg.username),temp,sizeof temp,&n)||n>=40)goto bad;
    if(recode("UTF-8",cfg.encoding,cfg.password,strlen(cfg.password),temp,sizeof temp,&n)||n>=40)goto bad;
    result=0;goto out;
bad:
    fprintf(stderr,"pcu20d: invalid configuration or inaccessible share at/after line %u (%s)\n",lineno,strerror(errno));
out:
    fclose(f);return result;
}
static int64_t milliseconds(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int io_all(int fd,void *buffer,size_t n,bool writing,int64_t deadline) {
    uint8_t *p=buffer;while(n&&!stopping) {
        int64_t left=deadline-milliseconds();if(left<=0)return fail(ETIMEDOUT);
        struct pollfd pollfd={fd,writing?POLLOUT:POLLIN,0};int rc=poll(&pollfd,1,(int)left);
        if(rc<0&&errno==EINTR)continue;if(rc<=0)return rc==0?fail(ETIMEDOUT):-1;
        ssize_t got=writing?send(fd,p,n,0):recv(fd,p,n,0);
        if(got<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        if(got<=0)return got==0?fail(ECONNRESET):-1;p+=got;n-=(size_t)got;
    }return stopping?fail(EINTR):0;
}
static int send_response(Session *s,uint32_t block,uint16_t error,const void *data,size_t n) {
    if(n>BODY_MAX)return fail(EMSGSIZE);uint8_t buffer[FRAME_MAX];
    p16(buffer,(uint16_t)(10+n));p32(buffer+2,block);p16(buffer+6,s->handle);p16(buffer+8,error);
    if(n)memcpy(buffer+10,data,n);
    return io_all(s->sock,buffer,n+10,true,milliseconds()+cfg.timeout_ms);
}
static int answer(Session *s,uint32_t block,uint16_t code) {return send_response(s,block,code,NULL,0);}
static int result_answer(Session *s,int32_t result) {uint8_t p[4];p32(p,(uint32_t)result);return send_response(s,s->block,0,p,4);}
static int field(const uint8_t *data,size_t length,size_t offset,size_t width,char *out,size_t cap) {
    if(offset>length||width>length-offset)return fail(EPROTO);
    const uint8_t *end=memchr(data+offset,0,width);if(!end)return fail(EPROTO);
    return recode(cfg.encoding,"UTF-8",(const char*)data+offset,(size_t)(end-data-offset),out,cap,NULL);
}
static uint32_t utf8_next(const unsigned char **cursor) {
    const unsigned char *p=*cursor;uint32_t c=*p++;
    if(c<128){*cursor=p;return c;}
    unsigned n;if((c&0xe0)==0xc0){c&=31;n=1;}else if((c&0xf0)==0xe0){c&=15;n=2;}else if((c&0xf8)==0xf0){c&=7;n=3;}else{*cursor=p;return 0xfffd;}
    for(unsigned i=0;i<n;i++){if((*p&0xc0)!=0x80){*cursor=p;return 0xfffd;}c=(c<<6)|(*p++&63);}*cursor=p;return c;
}
static uint32_t fold(uint32_t c) {
    if((c>='A'&&c<='Z')||(c>=0xc0&&c<=0xd6)||(c>=0xd8&&c<=0xde)||(c>=0x410&&c<=0x42f))return c+32;
    if(c>=0x400&&c<=0x40f)return c+80;
    if(c==0x178)return 0xff;if(c==0x152||c==0x160||c==0x17d)return c+1;return c;
}
static int namecmp(const char *a,const char *b) {
    const unsigned char *pa=(const unsigned char*)a,*pb=(const unsigned char*)b;
    while(*pa&&*pb){uint32_t x=fold(utf8_next(&pa)),y=fold(utf8_next(&pb));if(x!=y)return x<y?-1:1;}
    return *pa?1:*pb?-1:0;
}
static bool reserved(const char *s) {return !strncasecmp(s,".pcu20-",7);}
static bool valid_component(const char *s) {
    if(!*s||!strcmp(s,".")||!strcmp(s,"..")||reserved(s)||strlen(s)>NAME_MAX)return false;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++)if(*p<32||strchr("\\/:*?",*p))return false;
    return true;
}
static int independent_dir(int fd) {return openat(fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);}
/* Returns 1 for an existing unambiguous name, 0 for a new name, -1 on error. */
static int lookup(int parent,const char *requested,char out[NAME_MAX+1]) {
    int fd=independent_dir(parent);if(fd<0)return -1;DIR *dir=fdopendir(fd);if(!dir){close(fd);return -1;}
    int count=0,saved=0;struct dirent *de;
    for(;;){errno=0;de=readdir(dir);if(!de){saved=errno;break;}if(!namecmp(de->d_name,requested)){if(++count>1){saved=EACCES;break;}copystr(out,NAME_MAX+1,de->d_name);}}
    closedir(dir);if(saved)return fail(saved);if(!count&&copystr(out,NAME_MAX+1,requested))return -1;return count?1:0;
}
static Share *wire_share(const char *wire,char *parts,size_t cap,char **relative) {
    if(strncmp(wire,"\\\\",2)||strchr(wire,'/')||copystr(parts,cap,wire+2))return NULL;
    char *server=parts,*share=strchr(server,'\\');if(!share||share==server)return NULL;*share++=0;
    char *tail=strchr(share,'\\');if(tail)*tail++=0;else tail=share+strlen(share);
    for(size_t i=0;i<cfg.nshares;i++)if(!namecmp(cfg.shares[i].name,share)){*relative=tail;return &cfg.shares[i];}
    return NULL;
}
static int resolve(const char *wire,bool write,bool make_parents,Resolved *r) {
    memset(r,0,sizeof *r);r->parent=-1;char parts[2048],*tail;
    Share *sh=wire_share(wire,parts,sizeof parts,&tail);if(!sh|| (write&&sh->ro))return fail(EACCES);
    r->share=sh;int parent=independent_dir(sh->fd);if(parent<0)return -1;
    char *save,*part=strtok_r(tail,"\\",&save);
    if(!part){r->parent=parent;r->root=true;strcpy(r->name,".");return 0;}
    while(part) {
        if(!valid_component(part)){close(parent);return fail(EACCES);}
        char canonical[NAME_MAX+1];int exists=lookup(parent,part,canonical);if(exists<0){close(parent);return -1;}
        char *next=strtok_r(NULL,"\\",&save);
        if(!next) {
            struct stat st;if(exists&&(fstatat(parent,canonical,&st,AT_SYMLINK_NOFOLLOW)||S_ISLNK(st.st_mode))){close(parent);return fail(EACCES);}
            r->parent=parent;strcpy(r->name,canonical);return 0;
        }
        if(!exists&&make_parents&&mkdirat(parent,canonical,0770)){close(parent);return -1;}
        int child=openat(parent,canonical,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        int saved=errno;close(parent);errno=saved;if(child<0)return -1;parent=child;part=next;
    }
    close(parent);return fail(EINVAL);
}
static void unresolve(Resolved *r) {if(r->parent>=0)close(r->parent);r->parent=-1;}
static int share_lock(Share *sh) {
    if(sh->ro)return fail(EACCES);
    int fd=openat(sh->fd,".pcu20-lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||flock(fd,LOCK_EX|LOCK_NB)){int e=errno;close(fd);return fail(e?e:EACCES);}return fd;
}
static int lock_wire(const char *wire) {char parts[2048],*tail;Share *sh=wire_share(wire,parts,sizeof parts,&tail);return sh?share_lock(sh):fail(EACCES);}
static int local_write(int fd,const void *buffer,size_t n) {
    const uint8_t *p=buffer;while(n&&!stopping){ssize_t rc=write(fd,p,n);if(rc<0&&errno==EINTR)continue;if(rc<=0)return -1;p+=rc;n-=(size_t)rc;}return stopping?fail(EINTR):0;
}
static int start_write(Session *s) {
    if(!s->target_valid||s->target.share->ro)return fail(EACCES);if(s->staged)return 0;
    s->lock=share_lock(s->target.share);if(s->lock<0)return -1;
    int random=open("/dev/urandom",O_RDONLY|O_CLOEXEC);if(random<0)return -1;
    uint64_t nonce;ssize_t n=read(random,&nonce,sizeof nonce);close(random);if(n!=sizeof nonce)return fail(EIO);
    int temp=-1;
    for(unsigned attempt=0;attempt<16;attempt++) {
        snprintf(s->stage,sizeof s->stage,".pcu20-%ld-%016" PRIx64 "-%u",(long)getpid(),nonce,attempt);
        temp=openat(s->target.parent,s->stage,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(temp>=0)break;if(errno!=EEXIST)return -1;
    }
    if(temp<0)return -1;s->staged=true;
    struct stat st;mode_t mode=0600;off_t oldpos=0;
    if(s->file>=0) {
        if(fstat(s->file,&st)||(oldpos=lseek(s->file,0,SEEK_CUR))<0){close(temp);return -1;}mode=st.st_mode&0777;
        if(!cfg.truncate) {
            uint8_t buffer[32768];off_t pos=0;
            while((uint64_t)pos<cfg.max_file) {ssize_t got=pread(s->file,buffer,sizeof buffer,pos);if(got<0&&errno==EINTR)continue;if(got<0){close(temp);return -1;}if(!got)break;if((uint64_t)pos+(size_t)got>cfg.max_file||local_write(temp,buffer,(size_t)got)){close(temp);return -1;}pos+=got;}
            if(lseek(temp,oldpos,SEEK_SET)<0){close(temp);return -1;}
        }
    }
    if(fchmod(temp,mode)){close(temp);return -1;}if(s->file>=0)close(s->file);s->file=temp;return 0;
}
static int close_file(Session *s,bool commit) {
    int result=0,saved=0;
    if(commit&&s->target_valid&&s->created&&!s->staged&&start_write(s))result=-1;
    if(commit&&s->staged&&result==0&&fsync(s->file))result=-1;
    if(result)saved=errno;
    if(s->file>=0){if(close(s->file)&&!result){result=-1;saved=errno;}s->file=-1;}
    if(commit&&s->staged&&!result) {
        if(renameat(s->target.parent,s->stage,s->target.parent,s->target.name)){result=-1;saved=errno;}
        else {s->staged=false;if(fsync(s->target.parent)){result=-1;saved=errno;}}
    }
    if(s->staged){unlinkat(s->target.parent,s->stage,0);s->staged=false;}
    if(s->lock>=0){close(s->lock);s->lock=-1;}
    if(s->target_valid){unresolve(&s->target);s->target_valid=false;}
    if(result)errno=saved;return result;
}
static bool equal_secret(const char *a,const char *b) {
    size_t na=strlen(a),nb=strlen(b);volatile unsigned difference=(unsigned)(na^nb);
    for(size_t i=0;i<256;i++)difference|=(unsigned)((i<na?(unsigned char)a[i]:0)^(i<nb?(unsigned char)b[i]:0));return difference==0;
}
static bool pattern_match(const char *pattern,const char *name) {
    if(!strcmp(pattern,"*.*"))return true;
    const unsigned char *p=(const unsigned char*)pattern,*n=(const unsigned char*)name,*star=NULL,*retry=NULL;
    while(*n) {
        const unsigned char *pp=p,*nn=n;uint32_t pc=*p?utf8_next(&pp):0,nc=utf8_next(&nn);
        if(pc=='*'){star=pp;retry=n;p=pp;continue;}
        if(pc=='?'||fold(pc)==fold(nc)){p=pp;n=nn;continue;}
        if(star){p=star;utf8_next(&retry);n=retry;continue;}return false;
    }
    while(*p=='*')p++;return !*p;
}
static int entry_cmp(const void *a,const void *b) {const Entry *x=a,*y=b;if(x->directory!=y->directory)return x->directory?-1:1;return namecmp(x->name,y->name);}
static bool short_name(const char *s) {
    size_t base=0,extension=0;bool dot=false;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){
        if(*p=='.'){if(dot||!base)return false;dot=true;continue;}
        if(*p<33||strchr("\"+,/:;<=>[\\]|?*",*p))return false;
        if(dot){if(++extension>3)return false;}else if(++base>8)return false;
    }return base>0;
}
static int directory(Session *s,const uint8_t *data,size_t n) {
    if(n>10) {
        if(n!=274)return fail(EPROTO);char wire[2048];if(field(data,n,10,260,wire,sizeof wire))return -1;
        char *mask=strrchr(wire,'\\');if(!mask||!mask[1])return fail(EPROTO);*mask++=0;
        Resolved r;if(resolve(wire,false,false,&r))return -1;
        int fd=openat(r.parent,r.name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);unresolve(&r);if(fd<0)return -1;
        DIR *dir=fdopendir(fd);if(!dir){close(fd);return -1;}free(s->entries);s->entries=NULL;s->entry_count=s->entry_next=0;
        size_t allocated=0;struct dirent *de;int error=0;
        for(;;) {
            errno=0;de=readdir(dir);if(!de){error=errno;break;}
            if(!strcmp(de->d_name,".")||!strcmp(de->d_name,"..")||reserved(de->d_name))continue;
            struct stat st;if(fstatat(fd,de->d_name,&st,AT_SYMLINK_NOFOLLOW))continue;
            bool isdir=S_ISDIR(st.st_mode);if(!isdir&&!S_ISREG(st.st_mode))continue;
            if(!isdir&&!pattern_match(mask,de->d_name))continue;
            Entry e;memset(&e,0,sizeof e);e.directory=isdir;copystr(e.name,sizeof e.name,de->d_name);
            size_t namebytes;if(recode("UTF-8",cfg.encoding,de->d_name,strlen(de->d_name),(char*)e.body+20,260,&namebytes)){logmsg(1,"skipping unrepresentable directory entry");continue;}
            uint32_t attrs=isdir?16:32;if(!(st.st_mode&0222))attrs|=1;
            p32(e.body,attrs);
#ifdef __FreeBSD__
            p32(e.body+4,(uint32_t)st.st_birthtim.tv_sec);
#else
            p32(e.body+4,(uint32_t)st.st_ctim.tv_sec);
#endif
            p32(e.body+8,(uint32_t)st.st_atim.tv_sec);p32(e.body+12,(uint32_t)st.st_mtim.tv_sec);
            p32(e.body+16,isdir?0:st.st_size>UINT32_MAX?UINT32_MAX:(uint32_t)st.st_size);
            if(namebytes<=12&&short_name((const char*)e.body+20))memcpy(e.body+284,e.body+20,namebytes);
            if(s->entry_count==MAX_ENTRIES){error=EOVERFLOW;break;}
            if(s->entry_count==allocated){size_t next=allocated?allocated*2:32;if(next>MAX_ENTRIES)next=MAX_ENTRIES;Entry *v=realloc(s->entries,next*sizeof *v);if(!v){error=ENOMEM;break;}s->entries=v;allocated=next;}
            s->entries[s->entry_count++]=e;
        }
        closedir(dir);if(error)return fail(error);if(s->entry_count>1)qsort(s->entries,s->entry_count,sizeof *s->entries,entry_cmp);
    }
    if(s->entry_next<s->entry_count)return send_response(s,1,0,s->entries[s->entry_next++].body,297);
    if(s->block==65535){s->done=true;return answer(s,65535,0);}return answer(s,1,120);
}
static int goto_line(int fd,uint16_t line) {
    if(lseek(fd,0,SEEK_SET)<0)return -1;uint8_t buffer[4096];uint32_t lines=0;bool pending=false;uint64_t bytes=0;
    while(lines<line&&!stopping) {
        ssize_t n=read(fd,buffer,sizeof buffer);if(n<0&&errno==EINTR)continue;if(n<0)return -1;
        if(!n)return lines+(pending?1:0)==line?0:1;
        bytes+=(size_t)n;if(bytes>cfg.max_file)return fail(EFBIG);
        for(ssize_t i=0;i<n;i++) {
            pending=true;
            if(buffer[i]=='\n'){pending=false;if(++lines==line){if(lseek(fd,i+1-n,SEEK_CUR)<0)return -1;return 0;}}
        }
    }return stopping?-1:0;
}
static int one_line(int fd,uint8_t *out,size_t cap,size_t *length) {
    *length=0;while(*length<cap&&!stopping) {
        size_t want=cap-*length;if(want>4096)want=4096;ssize_t got=read(fd,out+*length,want);
        if(got<0&&errno==EINTR)continue;if(got<0)return -1;if(!got)return 0;
        uint8_t *lf=memchr(out+*length,'\n',(size_t)got);
        if(lf){size_t kept=(size_t)(lf-(out+*length))+1;if(lseek(fd,(off_t)kept-got,SEEK_CUR)<0)return -1;*length+=kept;return 0;}
        *length+=(size_t)got;
    }return stopping?fail(EINTR):0;
}
static int dispatch(Session *s,const uint8_t *data,size_t n,uint16_t cmd) {
    char wire[2048];Resolved r={.parent=-1};int rc=0,lock=-1;
    if(!s->authenticated) {
        if(cmd!=1||n!=350)return answer(s,s->block,10);
        char user[256],password[256];if(field(data,n,270,40,user,sizeof user)||field(data,n,310,40,password,sizeof password))return -1;
        s->authenticated=cfg.compatibility||(equal_secret(user,cfg.username)&&equal_secret(password,cfg.password));
        if(!s->authenticated)s->done=true;return answer(s,s->authenticated?1:s->block,s->authenticated?0:10);
    }
    switch(cmd) {
    case 0: case 11: {
        if(n!=10)return fail(EPROTO);uint8_t version[24]={0};memcpy(version,"V06.02.56",9);p32(version+20,0x62000001);
        s->done=true;return send_response(s,s->block,0,version,cmd==11?24:20);
    }
    case 10: s->done=true;return result_answer(s,-1);
    case 5: if(n!=10)return fail(EPROTO);s->done=true;return answer(s,s->block,0);
    case 4: return directory(s,data,n);
    case 12: {
        if(n!=278||field(data,n,10,260,wire,sizeof wire))return fail(EPROTO);
        if(close_file(s,false)||resolve(wire,false,false,&s->target))return -1;s->target_valid=true;
        if(s->target.root)return fail(EISDIR);struct stat st;
        s->file=openat(s->target.parent,s->target.name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        s->created=s->file<0&&errno==ENOENT;
        if(s->file<0&&!s->created)return -1;
        if(s->created&&s->target.share->ro)return fail(EACCES);
        if(s->file>=0&&(fstat(s->file,&st)||!S_ISREG(st.st_mode)||(uint64_t)st.st_size>cfg.max_file))return fail(EACCES);
        s->lines_sent=false;s->line_length=0;return answer(s,1,0);
    }
    case 2: {
        if(start_write(s))return -1;off_t pos=lseek(s->file,0,SEEK_CUR);
        if(pos<0||(uint64_t)pos>cfg.max_file||n-10>cfg.max_file-(uint64_t)pos)return fail(EFBIG);
        if(local_write(s->file,data+10,n-10))return -1;return answer(s,s->block,0);
    }
    case 3: {
        if(n!=14||!s->target_valid)return fail(EPROTO);uint32_t count=u32(data+10);if(!count||count>BODY_MAX)return fail(EPROTO);
        uint8_t buffer[BODY_MAX];ssize_t got=0;if(s->file>=0){do{got=read(s->file,buffer,count);}while(got<0&&errno==EINTR&&!stopping);if(got<0)return -1;}
        return send_response(s,s->block,0,buffer,(size_t)got);
    }
    case 6: case 22:
        if(n!=10)return fail(EPROTO);s->done=true;
        if(cmd==22&&!s->target_valid)return answer(s,1,11);
        if(close_file(s,true))return -1;return answer(s,cmd==22?255:65535,0);
    case 14: {
        if(n!=18||s->file<0)return fail(EPROTO);int seek=goto_line(s->file,u16(data+10));if(seek<0)return -1;return answer(s,65535,seek?141:0);
    }
    case 13: {
        if(n!=18||s->file<0)return fail(EPROTO);
        if(!s->lines_sent) {
            unsigned lines=u16(data+10);size_t limit=u16(data+14);if(limit>BODY_MAX)limit=BODY_MAX;s->line_length=0;
            uint8_t buffer[BODY_MAX+1];
            for(unsigned i=0;i<lines;i++) {
                off_t position=lseek(s->file,0,SEEK_CUR);size_t length;if(position<0||one_line(s->file,buffer,limit-s->line_length+1,&length))return -1;
                if(length>limit-s->line_length){if(lseek(s->file,position,SEEK_SET)<0)return -1;break;}
                if(!length)break;memcpy(s->linebuf+s->line_length,buffer,length);s->line_length+=length;
            }
            uint8_t summary[8]={0};p32(summary,lines);if(send_response(s,65535,0,summary,8))return -1;s->lines_sent=true;
        }
        return s->line_length?send_response(s,1,0,s->linebuf,s->line_length):0;
    }
    case 7:
        if(n!=274||field(data,n,10,260,wire,sizeof wire)||resolve(wire,false,false,&r))return -1;
        {struct stat st;int result=fstatat(r.parent,r.name,&st,AT_SYMLINK_NOFOLLOW);unresolve(&r);s->done=true;return result_answer(s,result?-1:0);}
    case 8: case 30: case 31:
        if(n!=270||field(data,n,10,260,wire,sizeof wire))return fail(EPROTO);
        lock=lock_wire(wire);if(lock<0)return -1;
        rc=resolve(wire,true,cmd==8,&r);
        if(!rc&&r.root)rc=fail(EACCES);
        if(!rc)rc=cmd==8?mkdirat(r.parent,r.name,0770):unlinkat(r.parent,r.name,cmd==31?AT_REMOVEDIR:0);
        {int saved=errno;unresolve(&r);close(lock);errno=saved;}
        if(rc)return -1;s->done=true;return result_answer(s,0);
    case 9: {
        if(n!=530||field(data,n,10,260,wire,sizeof wire))return fail(EPROTO);char dest[2048];
        if(field(data,n,270,260,dest,sizeof dest))return -1;
        Resolved to={.parent=-1};lock=lock_wire(wire);if(lock<0)return -1;
        rc=resolve(wire,true,false,&r);if(!rc)rc=resolve(dest,true,false,&to);int second=-1;
        if(!rc&&to.share!=r.share){second=share_lock(to.share);if(second<0)rc=-1;}
        struct stat st;
        if(!rc&&(r.root||to.root))rc=fail(EACCES);
        if(!rc&&fstatat(to.parent,to.name,&st,AT_SYMLINK_NOFOLLOW)==0)rc=fail(EEXIST);
        else if(!rc&&errno!=ENOENT)rc=-1;
        if(!rc)rc=renameat(r.parent,r.name,to.parent,to.name);
        {int saved=errno;unresolve(&r);unresolve(&to);if(second>=0)close(second);close(lock);errno=saved;}
        if(rc)return -1;s->done=true;return answer(s,s->block,0);
    }
    default:s->done=true;return answer(s,1,11);
    }
}
static void client(int sock) {
    Session *s=calloc(1,sizeof *s);if(!s){close(sock);_exit(1);}s->sock=sock;s->file=s->lock=-1;s->target.parent=-1;
    uint8_t data[FRAME_MAX];
    while(!stopping&&!s->done) {
        int64_t deadline=milliseconds()+cfg.timeout_ms;
        if(io_all(sock,data,2,false,deadline))break;size_t length=u16(data);if(length<10)break;
        if(io_all(sock,data+2,length-2,false,deadline))break;
        s->block=u32(data+2);s->handle=u16(data+6);uint16_t cmd=u16(data+8);
        logmsg(3,"command=%u block=%" PRIu32 " handle=%u length=%zu",cmd,s->block,s->handle,length);
        if(dispatch(s,data,length,cmd)) {
            logmsg(1,"command=%u failed: %s",cmd,strerror(errno));
            if(!stopping) {
                if(cmd==4)answer(s,1,120);
                else if(cmd==7||cmd==8||cmd==30||cmd==31)result_answer(s,-1);
                else answer(s,cmd==2||cmd==3||cmd==12?65535:s->block,cmd==12?40:10);
            }break;
        }
    }
    close_file(s,false);free(s->entries);free(s);close(sock);_exit(0);
}
static void on_signal(int sig) {if(sig!=SIGCHLD)stopping=1;}
static int serve(void) {
    struct sigaction sa;memset(&sa,0,sizeof sa);sa.sa_handler=on_signal;sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM,&sa,NULL);sigaction(SIGINT,&sa,NULL);sigaction(SIGCHLD,&sa,NULL);signal(SIGPIPE,SIG_IGN);
    struct pollfd listeners[MAX_PORTS];size_t bound=0;pid_t children[MAX_CLIENTS]={0};int status=1;
    for(size_t i=0;i<cfg.nports;i++) {
        int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)goto out;
        int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);fcntl(fd,F_SETFD,FD_CLOEXEC);
        struct sockaddr_in address;memset(&address,0,sizeof address);address.sin_family=AF_INET;
#ifdef __FreeBSD__
        address.sin_len=sizeof address;
#endif
        address.sin_port=htons(cfg.ports[i]);inet_pton(AF_INET,cfg.host,&address.sin_addr);
        if(bind(fd,(struct sockaddr*)&address,sizeof address)||listen(fd,cfg.max_clients)){int saved=errno;close(fd);errno=saved;goto out;}
        listeners[bound++]=(struct pollfd){fd,POLLIN,0};
    }
    for(size_t i=0;i<bound;i++)logmsg(2,"listening %s:%u",cfg.host,cfg.ports[i]);
    while(!stopping) {
        int childstatus;pid_t exited;while((exited=waitpid(-1,&childstatus,WNOHANG))>0)for(int i=0;i<cfg.max_clients;i++)if(children[i]==exited)children[i]=0;
        int ready=poll(listeners,(nfds_t)bound,250);if(ready<0&&errno==EINTR)continue;if(ready<0)goto out;
        for(size_t i=0;i<bound&&!stopping;i++)if(listeners[i].revents&POLLIN) {
            struct sockaddr_in address;socklen_t size=sizeof address;int fd=accept(listeners[i].fd,(struct sockaddr*)&address,&size);
            if(fd<0){if(errno==EINTR)continue;logmsg(1,"accept: %s",strerror(errno));continue;}
            uint32_t ip=ntohl(address.sin_addr.s_addr);bool allowed=false;
            for(size_t j=0;j<cfg.nnets;j++)if((ip&cfg.nets[j].mask)==cfg.nets[j].address)allowed=true;
            int slot;for(slot=0;slot<cfg.max_clients&&children[slot];slot++);
            if(!allowed||slot==cfg.max_clients){close(fd);continue;}
            int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0){close(fd);continue;}
            int one=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one);
            pid_t childpid=fork();if(childpid<0){logmsg(0,"fork: %s",strerror(errno));close(fd);continue;}
            if(!childpid){for(size_t j=0;j<bound;j++)close(listeners[j].fd);client(fd);}
            children[slot]=childpid;close(fd);
        }
    }status=0;
out:
    if(status)logmsg(0,"listener failure: %s",strerror(errno));
    for(size_t i=0;i<bound;i++)close(listeners[i].fd);
    for(int i=0;i<cfg.max_clients;i++)if(children[i]>0)kill(children[i],SIGTERM);
    int64_t deadline=milliseconds()+3000;
    for(;;){pid_t pid=waitpid(-1,NULL,WNOHANG);if(pid<0&&errno==ECHILD)break;if(pid>0){for(int i=0;i<cfg.max_clients;i++)if(children[i]==pid)children[i]=0;continue;}if(milliseconds()>=deadline)break;struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
    for(int i=0;i<cfg.max_clients;i++)if(children[i]>0)kill(children[i],SIGKILL);
    while(waitpid(-1,NULL,0)>0||errno==EINTR){}return status;
}
int main(int argc,char **argv) {
    const char *filename="/usr/local/etc/pcu20d.ini";bool check=false;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--version")){puts("pcu20d " VERSION " (native C, FreeBSD)");return 0;}
        if(!strcmp(argv[i],"--check-config"))check=true;
        else if((!strcmp(argv[i],"-c")||!strcmp(argv[i],"--config"))&&i+1<argc)filename=argv[++i];
        else {fprintf(stderr,"Usage: pcu20d [-c file.ini] [--check-config] [--version]\n");return 1;}
    }
    umask(0027);if(read_config(filename))return 1;
    if(check){printf("Configuration OK: %zu share(s), %zu port(s)\n",cfg.nshares,cfg.nports);return 0;}
    return serve();
}
