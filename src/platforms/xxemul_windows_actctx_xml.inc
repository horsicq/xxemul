/* Bounded original XML/identity reader for the default Win32 activation profile.
 * No external entities, general XML engine, COM metadata or trust validation. */
#define WIN_ACTCTX_XML_MAX 0x10000u
#define WIN_ACTCTX_ASSEMBLIES 0x20u
#define WIN_ACTCTX_FILES 0x80u
#define WIN_ACTCTX_STORE 0x40u
#define WIN_ACTCTX_PATH 0x400u
#define WIN_ACTCTX_DEPTH 0x10u
#define WIN_ACTCTX_NS 0x20u
#define WIN_ACTCTX_ATTRS 0x18u

typedef struct win_actctx_identity {
    char name[0x80], type[0x18], arch[0x10], token[0x11], language[0x20];
    uint64_t version;
    uint8_t has_version;
} win_actctx_identity;
typedef struct win_actctx_dependency {
    win_actctx_identity identity;
    uint8_t has_identity;
} win_actctx_dependency;
typedef struct win_actctx_xml_file {
    char name[0x30], hash[0x80], hashalg[0x20];
} win_actctx_xml_file;
typedef struct win_actctx_redirect {
    uint64_t low, high, replacement;
    uint16_t dependency;
} win_actctx_redirect;
typedef struct win_actctx_document {
    win_actctx_identity identity;
    win_actctx_dependency dependencies[WIN_ACTCTX_ASSEMBLIES];
    win_actctx_xml_file files[WIN_ACTCTX_FILES];
    win_actctx_redirect redirects[WIN_ACTCTX_ASSEMBLIES];
    uint16_t dependency_count, file_count, redirect_count;
    uint8_t has_identity, no_inheritable, policy;
} win_actctx_document;
typedef struct win_actctx_xml_attribute { char name[0x40], value[0x800]; } win_actctx_xml_attribute;
typedef struct win_actctx_xml_ns { char prefix[0x20], uri[0x100]; } win_actctx_xml_ns;
typedef struct win_actctx_xml_frame { char name[0x40]; unsigned ns_before, role, dependency; } win_actctx_xml_frame;
enum { ACXML_ASSEMBLY=1, ACXML_DEPENDENCY, ACXML_DEPENDENT, ACXML_IDENTITY,
       ACXML_FILE, ACXML_REDIRECT, ACXML_METADATA, ACXML_NOINHERITABLE };

static int win_acxml_copy(char *to, size_t capacity, const char *from)
{
    size_t n=strlen(from); if(n>=capacity)return 0; memcpy(to,from,n+1u);return 1;
}
static int win_acxml_ascii(const char *s)
{
    const unsigned char *p=(const unsigned char*)s;
    for(;*p;++p)if(*p<0x20u||*p>0x7eu)return 0;
    return 1;
}
static int win_acxml_equal(const char *a,const char *b)
{
    while(*a&&*b){if(tolower((unsigned char)*a++)!=tolower((unsigned char)*b++))return 0;}
    return *a==*b;
}
static int win_acxml_version(const char *text,uint64_t *out)
{
    uint64_t value=0;unsigned part;
    for(part=0;part<4u;++part){
        uint32_t n=0;unsigned digits=0;
        while(*text>='0'&&*text<='9'){if(++digits>5u)return 0;n=n*10u+(unsigned)(*text++-'0');if(n>0xffffu)return 0;}
        if(!digits)return 0;
        value=(value<<16)|n;
        if(part<3u){if(*text++!='.')return 0;}else if(*text)return 0;
    }
    *out=value;return 1;
}
static int win_acxml_safe_leaf(const char *s)
{
    const unsigned char *p=(const unsigned char*)s;
    if(!*p||s[strlen(s)-1u]=='.'||!strcmp(s,".")||!strcmp(s,".."))return 0;
    for(;*p;++p)if(*p<0x21u||*p>0x7eu||strchr("/\\:*?\"<>|",*p))return 0;
    return 1;
}
static const char *win_acxml_attr(const win_actctx_xml_attribute *a,unsigned n,const char *name)
{
    unsigned i;for(i=0;i<n;++i)if(!strcmp(a[i].name,name))return a[i].value;return NULL;
}
static int win_acxml_is_xmlns(const char *name)
{return !strcmp(name,"xmlns")||!strncmp(name,"xmlns:",6u);}
static int win_acxml_identity(win_actctx_identity *id,const win_actctx_xml_attribute *a,unsigned n,int version_required)
{
    unsigned i;const char *s;memset(id,0,sizeof(*id));
    for(i=0;i<n;++i){
        if(win_acxml_is_xmlns(a[i].name))continue;
        if(strcmp(a[i].name,"name")&&strcmp(a[i].name,"type")&&strcmp(a[i].name,"version")&&
           strcmp(a[i].name,"processorArchitecture")&&strcmp(a[i].name,"publicKeyToken")&&strcmp(a[i].name,"language"))return 50;
        if(!win_acxml_ascii(a[i].value))return 50;
    }
    s=win_acxml_attr(a,n,"name");if(!s||!win_acxml_safe_leaf(s)||!win_acxml_copy(id->name,sizeof(id->name),s))return 14001;
    s=win_acxml_attr(a,n,"type");if(!s||!win_acxml_copy(id->type,sizeof(id->type),s))return 14001;
    if(strcmp(s,"win32")&&strcmp(s,"win32-policy"))return 50;
    s=win_acxml_attr(a,n,"version");if(s){if(!win_acxml_version(s,&id->version))return 14001;id->has_version=1u;}else if(version_required)return 14001;
    s=win_acxml_attr(a,n,"processorArchitecture");if(s&&!win_acxml_copy(id->arch,sizeof(id->arch),s))return 14001;
    if(s&&!win_acxml_equal(s,"x86")&&!win_acxml_equal(s,"amd64")&&strcmp(s,"*"))return 50;
    s=win_acxml_attr(a,n,"publicKeyToken");if(s){
        if(strlen(s)!=0x10u)return 14001;
        for(i=0;i<0x10u;++i)if(!isxdigit((unsigned char)s[i]))return 14001;
        if(!win_acxml_copy(id->token,sizeof(id->token),s))return 14001;
    }
    s=win_acxml_attr(a,n,"language");if(s&&!win_acxml_copy(id->language,sizeof(id->language),s))return 14001;
    return 0;
}
static int win_acxml_utf8_append(char *out,size_t capacity,size_t *n,uint32_t cp)
{
    unsigned count=cp<0x80u?1u:cp<0x800u?2u:cp<0x10000u?3u:4u;
    if(!cp||(cp<0x20u&&cp!=9u&&cp!=10u&&cp!=13u)||cp==0xfffeu||cp==0xffffu||
       cp>0x10ffffu||(cp>=0xd800u&&cp<=0xdfffu)||count>=capacity-*n)return 0;
    if(count==1u)out[(*n)++]=(char)cp;
    else{
        unsigned shift=(count-1u)*6u;out[(*n)++]=(char)((count==2u?0xc0u:count==3u?0xe0u:0xf0u)|(cp>>shift));
        while(shift){shift-=6u;out[(*n)++]=(char)(0x80u|((cp>>shift)&0x3fu));}
    }
    return 1;
}
static char *win_acxml_text(const uint8_t *raw,size_t size,int *error)
{
    char *out;size_t n=0,i=0;int wide=0,big=0;
    *error=14001;if(!size||size>WIN_ACTCTX_XML_MAX)return NULL;
    out=(char*)malloc(WIN_ACTCTX_XML_MAX*2u+1u);if(!out){*error=8;return NULL;}
    if(size>=2u&&((raw[0]==0xffu&&raw[1]==0xfeu)||(raw[0]==0xfeu&&raw[1]==0xffu))){wide=1;big=raw[0]==0xfeu;i=2u;if(size&1u)goto bad;}
    else if(size>=3u&&raw[0]==0xefu&&raw[1]==0xbbu&&raw[2]==0xbfu)i=3u;
    while(i<size){
        uint32_t cp;unsigned k,count;
        if(wide){
            cp=big?((uint32_t)raw[i]<<8)|raw[i+1u]:raw[i]|((uint32_t)raw[i+1u]<<8);i+=2u;
            if(cp>=0xd800u&&cp<=0xdbffu){uint32_t low;if(i+2u>size)goto bad;low=big?((uint32_t)raw[i]<<8)|raw[i+1u]:raw[i]|((uint32_t)raw[i+1u]<<8);i+=2u;if(low<0xdc00u||low>0xdfffu)goto bad;cp=0x10000u+((cp-0xd800u)<<10)+(low-0xdc00u);}
            else if(cp>=0xdc00u&&cp<=0xdfffu)goto bad;
        }else{
            unsigned char first=raw[i++];cp=first;
            if(first>=0x80u){
                count=first>=0xc2u&&first<=0xdfu?1u:first>=0xe0u&&first<=0xefu?2u:first>=0xf0u&&first<=0xf4u?3u:0u;if(!count||count>size-i)goto bad;
                cp=first&(count==1u?0x1fu:count==2u?0x0fu:7u);
                for(k=0;k<count;++k){if((raw[i]&0xc0u)!=0x80u)goto bad;cp=(cp<<6)|(raw[i++]&0x3fu);}
                if((count==1u&&cp<0x80u)||(count==2u&&cp<0x800u)||(count==3u&&cp<0x10000u))goto bad;
            }
        }
        if(!cp||(cp<0x20u&&cp!=9u&&cp!=10u&&cp!=13u)||!win_acxml_utf8_append(out,WIN_ACTCTX_XML_MAX*2u+1u,&n,cp))goto bad;
    }
    out[n]=0;*error=0;return out;
bad:free(out);return NULL;
}
static int win_acxml_name_char(unsigned char c,int first)
{return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||c=='_'||c==':'||(!first&&((c>='0'&&c<='9')||c=='-'||c=='.'));}
static int win_acxml_name(const char **p,char *out,size_t capacity)
{
    size_t n=0;if(!win_acxml_name_char((unsigned char)**p,1))return 0;
    while(win_acxml_name_char((unsigned char)**p,n==0u)){if(n+1u>=capacity)return 0;out[n++]=*(*p)++;}
    out[n]=0;return 1;
}
static void win_acxml_space(const char **p){while(**p&&isspace((unsigned char)**p))++*p;}
static int win_acxml_entity(const char **p,uint32_t *value)
{
    const char *begin=*p;size_t k=0;
    while(begin[k]&&begin[k]!=';'&&k<0x20u)++k;
    if(begin[k]!=';')return 0;
    if(k==3u&&!memcmp(begin,"amp",3u))*value='&';
    else if(k==2u&&!memcmp(begin,"lt",2u))*value='<';
    else if(k==2u&&!memcmp(begin,"gt",2u))*value='>';
    else if(k==4u&&!memcmp(begin,"quot",4u))*value='"';
    else if(k==4u&&!memcmp(begin,"apos",4u))*value='\'';
    else if(k>1u&&begin[0]=='#'){
        uint32_t cp=0;size_t j=1u;unsigned base=10u;
        if(begin[j]=='x'){base=16u;++j;}if(j==k)return 0;
        for(;j<k;++j){
            unsigned digit;
            if(begin[j]>='0'&&begin[j]<='9')digit=(unsigned)(begin[j]-'0');
            else if(base==16u&&begin[j]>='a'&&begin[j]<='f')digit=(unsigned)(begin[j]-'a')+10u;
            else if(base==16u&&begin[j]>='A'&&begin[j]<='F')digit=(unsigned)(begin[j]-'A')+10u;
            else return 0;
            if(digit>=base||cp>(0x10ffffu-digit)/base)return 0;
            cp=cp*base+digit;
        }
        if(!cp||(cp<0x20u&&cp!=9u&&cp!=10u&&cp!=13u)||cp==0xfffeu||cp==0xffffu||
           cp>0x10ffffu||(cp>=0xd800u&&cp<=0xdfffu))return 0;
        *value=cp;
    }else return 0;
    *p+=k+1u;return 1;
}
static int win_acxml_value(const char **p,char *out,size_t capacity)
{
    char quote=*(*p)++;size_t n=0;if(quote!='\''&&quote!='"')return 0;
    while(**p&&**p!=quote){
        unsigned char c=(unsigned char)*(*p)++;
        if(c=='<')return 0;
        if(c=='&'){
            uint32_t cp;
            if(!win_acxml_entity(p,&cp)||!win_acxml_utf8_append(out,capacity,&n,cp))return 0;
            continue;
        }
        if(n+1u>=capacity)return 0;
        out[n++]=(char)c;
    }
    if(**p!=quote)return 0;
    ++*p;out[n]=0;return 1;
}
static int win_acxml_qname(const char *name)
{
    const char *colon=strchr(name,':');
    if(!((name[0]>='A'&&name[0]<='Z')||(name[0]>='a'&&name[0]<='z')||name[0]=='_'))return 0;
    if(!colon)return 1;
    return ((colon[1]>='A'&&colon[1]<='Z')||(colon[1]>='a'&&colon[1]<='z')||colon[1]=='_')&&!strchr(colon+1u,':');
}
static int win_acxml_pi(const char **p,int at_start,int wide)
{
    const char *cursor=*p+2u;char target[0x40];
    if(!win_acxml_name(&cursor,target,sizeof(target)))return 14001;
    if(win_acxml_equal(target,"xml")){
        unsigned phase=0u;
        if(strcmp(target,"xml")||!at_start)return 14001;
        for(;;){
            char name[0x40],value[0x40];const char *begin;int separated=isspace((unsigned char)*cursor);
            win_acxml_space(&cursor);
            if(cursor[0]=='?'&&cursor[1]=='>'){if(!phase)return 14001;*p=cursor+2u;return 0;}
            if(!separated||!win_acxml_name(&cursor,name,sizeof(name)))return 14001;
            win_acxml_space(&cursor);if(*cursor++!='=')return 14001;win_acxml_space(&cursor);begin=cursor;
            if(!win_acxml_value(&cursor,value,sizeof(value))||memchr(begin,'&',(size_t)(cursor-begin)))return 14001;
            if(!phase){if(strcmp(name,"version")||strcmp(value,"1.0"))return 14001;phase=1u;}
            else if(phase==1u&&!strcmp(name,"encoding")){
                if(!win_acxml_equal(value,wide?"UTF-16":"UTF-8"))return 50;
                phase=2u;
            }else if(phase<=2u&&!strcmp(name,"standalone")){
                if(strcmp(value,"yes")&&strcmp(value,"no"))return 14001;
                phase=3u;
            }else return 14001;
        }
    }
    if(!(cursor[0]=='?'&&cursor[1]=='>')&&!isspace((unsigned char)*cursor))return 14001;
    {const char *end=strstr(cursor,"?>");if(!end)return 14001;*p=end+2u;return 0;}
}
static const char *win_acxml_namespace(const win_actctx_xml_ns *ns,unsigned count,const char *name,const char **local)
{
    const char *colon=strchr(name,':');size_t n=colon?(size_t)(colon-name):0u;unsigned i;
    if(!win_acxml_qname(name))return NULL;
    *local=colon?colon+1u:name;if(colon&&(colon==name||!colon[1]||strchr(colon+1u,':')))return NULL;
    for(i=count;i>0u;--i)if(strlen(ns[i-1u].prefix)==n&&!memcmp(ns[i-1u].prefix,name,n))return ns[i-1u].uri;
    if(n==3u&&!memcmp(name,"xml",3u))return "http://www.w3.org/XML/1998/namespace";
    return n?NULL:"";
}
static int win_actctx_parse_xml(const uint8_t *raw,size_t size,win_actctx_document *doc,int application)
{
    char *text,*p;win_actctx_xml_frame stack[WIN_ACTCTX_DEPTH];win_actctx_xml_ns namespaces[WIN_ACTCTX_NS];
    win_actctx_xml_attribute *attributes;unsigned depth=0,ns_count=0,root_seen=0,root_closed=0,root_content=0;int error=0;
    memset(doc,0,sizeof(*doc));text=win_acxml_text(raw,size,&error);if(!text)return error;
    attributes=(win_actctx_xml_attribute*)calloc(WIN_ACTCTX_ATTRS,sizeof(*attributes));if(!attributes){free(text);return 8;}p=text;
#define ACXML_FAIL(code) do{error=(code);goto done;}while(0)
    while(*p){
        char name[0x40];const char *local,*uri;unsigned n=0,i,ns_before=ns_count,role=0,dep=0;int empty=0;
        if(*p!='<'){
            if(!depth||stack[depth-1u].role!=ACXML_METADATA){if(!isspace((unsigned char)*p))ACXML_FAIL(14001);}
            else if(!strncmp(p,"]]>",3u))ACXML_FAIL(14001);
            else if(*p=='&'){
                const char *cursor=p+1u;uint32_t cp;
                if(!win_acxml_entity(&cursor,&cp))ACXML_FAIL(14001);
                p=(char*)cursor;continue;
            }
            ++p;continue;
        }
        if(!strncmp(p,"<!--",4u)){char *end=strstr(p+4u,"-->");if(!end||strstr(p+4u,"--")!=end)ACXML_FAIL(14001);p=end+3u;continue;}
        if(!strncmp(p,"<?",2u)){
            const char *cursor=p;int wide=size>=2u&&((raw[0]==0xffu&&raw[1]==0xfeu)||(raw[0]==0xfeu&&raw[1]==0xffu));
            error=win_acxml_pi(&cursor,p==text,wide);if(error)goto done;p=(char*)cursor;continue;
        }
        if(!strncmp(p,"<!",2u))ACXML_FAIL(50);
        ++p;
        if(*p=='/'){
            const char *cursor=++p;if(!win_acxml_name(&cursor,name,sizeof(name)))ACXML_FAIL(14001);win_acxml_space(&cursor);
            if(*cursor!='>'||!depth||strcmp(stack[depth-1u].name,name))ACXML_FAIL(14001);
            ns_count=stack[depth-1u].ns_before;--depth;if(!depth)root_closed=1u;p=(char*)cursor+1u;continue;
        }
        if(root_closed||depth==WIN_ACTCTX_DEPTH)ACXML_FAIL(root_closed?14001:50);
        {const char *cursor=p;if(!win_acxml_name(&cursor,name,sizeof(name)))ACXML_FAIL(14001);p=(char*)cursor;}
        for(;;){
            const char *cursor=p;int separated=isspace((unsigned char)*cursor);win_acxml_space(&cursor);p=(char*)cursor;
            if(*p=='>'){++p;break;}if(*p=='/'&&p[1]=='>'){p+=2u;empty=1;break;}
            if(!separated)ACXML_FAIL(14001);
            if(n==WIN_ACTCTX_ATTRS)ACXML_FAIL(50);
            cursor=p;
            if(!win_acxml_name(&cursor,attributes[n].name,sizeof(attributes[n].name)))ACXML_FAIL(14001);
            if(!win_acxml_qname(attributes[n].name))ACXML_FAIL(14001);
            for(i=0;i<n;++i)if(!strcmp(attributes[i].name,attributes[n].name))ACXML_FAIL(14001);
            win_acxml_space(&cursor);if(*cursor++!='=')ACXML_FAIL(14001);win_acxml_space(&cursor);
            if(!win_acxml_value(&cursor,attributes[n].value,sizeof(attributes[n].value)))ACXML_FAIL(14001);
            p=(char*)cursor;++n;
        }
        for(i=0;i<n;++i)if(!strcmp(attributes[i].name,"xmlns")||!strncmp(attributes[i].name,"xmlns:",6u)){
            const char *prefix=attributes[i].name[5]==':'?attributes[i].name+6u:"";
            const char *binding=attributes[i].value;
            if(!strcmp(prefix,"xmlns")||!strcmp(binding,"http://www.w3.org/2000/xmlns/")||
               (!strcmp(prefix,"xml")&&strcmp(binding,"http://www.w3.org/XML/1998/namespace"))||
               (strcmp(prefix,"xml")&&!strcmp(binding,"http://www.w3.org/XML/1998/namespace"))||
               (*prefix&&!*binding))ACXML_FAIL(14001);
            if(ns_count==WIN_ACTCTX_NS||!win_acxml_copy(namespaces[ns_count].prefix,sizeof(namespaces[0].prefix),prefix)||!win_acxml_copy(namespaces[ns_count].uri,sizeof(namespaces[0].uri),attributes[i].value))ACXML_FAIL(50);
            ++ns_count;
        }
        for(i=0u;i<n;++i)if(!win_acxml_is_xmlns(attributes[i].name)){
            const char *attribute_local=attributes[i].name,*attribute_uri="";unsigned j;
            if(strchr(attributes[i].name,':'))attribute_uri=win_acxml_namespace(namespaces,ns_count,attributes[i].name,&attribute_local);
            if(!attribute_uri)ACXML_FAIL(14001);
            for(j=0u;j<i;++j)if(!win_acxml_is_xmlns(attributes[j].name)){
                const char *prior_local=attributes[j].name,*prior_uri="";
                if(strchr(attributes[j].name,':'))prior_uri=win_acxml_namespace(namespaces,ns_count,attributes[j].name,&prior_local);
                if(!prior_uri||(!strcmp(attribute_uri,prior_uri)&&!strcmp(attribute_local,prior_local)))ACXML_FAIL(14001);
            }
        }
        uri=win_acxml_namespace(namespaces,ns_count,name,&local);if(!uri)ACXML_FAIL(14001);
        if(depth&&stack[depth-1u].role==ACXML_ASSEMBLY&&!strcmp(uri,"urn:schemas-microsoft-com:asm.v1")){
            int identity=!strcmp(local,"assemblyIdentity"),marker=!strcmp(local,"noInheritable");
            if(identity&&root_content)ACXML_FAIL(14001);
            if(!application&&!doc->has_identity&&!identity&&!marker)ACXML_FAIL(14001);
            if(!identity&&!marker)root_content=1u;
        }
        if(depth&&stack[depth-1u].role==ACXML_METADATA)role=ACXML_METADATA;
        else if(strcmp(uri,"urn:schemas-microsoft-com:asm.v1")){
            if(depth&&stack[depth-1u].role==ACXML_FILE&&!strcmp(uri,"urn:schemas-microsoft-com:asm.v2")&&!strcmp(local,"hash"))role=ACXML_METADATA;
            else ACXML_FAIL(50);
        }else if(!depth){
            const char *v=win_acxml_attr(attributes,n,"manifestVersion");if(root_seen++||strcmp(local,"assembly")||!v||strcmp(v,"1.0"))ACXML_FAIL(14001);role=ACXML_ASSEMBLY;
        }else if(!strcmp(local,"assemblyIdentity")){
            unsigned parent=stack[depth-1u].role;win_actctx_identity *id;
            if(parent==ACXML_ASSEMBLY){if(doc->has_identity)ACXML_FAIL(14001);id=&doc->identity;doc->has_identity=1u;}
            else if(parent==ACXML_DEPENDENT){dep=stack[depth-1u].dependency;if(doc->dependencies[dep].has_identity)ACXML_FAIL(14001);id=&doc->dependencies[dep].identity;doc->dependencies[dep].has_identity=1u;}
            else ACXML_FAIL(14001);
            error=win_acxml_identity(id,attributes,n,parent==ACXML_ASSEMBLY||!doc->policy);if(error)goto done;
            if(parent==ACXML_ASSEMBLY)doc->policy=!strcmp(id->type,"win32-policy");else if(strcmp(id->type,"win32"))ACXML_FAIL(14001);
            role=ACXML_IDENTITY;
        }else if(!strcmp(local,"dependency")&&stack[depth-1u].role==ACXML_ASSEMBLY)role=ACXML_DEPENDENCY;
        else if(!strcmp(local,"dependentAssembly")&&stack[depth-1u].role==ACXML_DEPENDENCY){
            if(doc->dependency_count==WIN_ACTCTX_ASSEMBLIES)ACXML_FAIL(50);
            dep=doc->dependency_count++;role=ACXML_DEPENDENT;
        }else if(!strcmp(local,"bindingRedirect")&&stack[depth-1u].role==ACXML_DEPENDENT&&doc->policy){
            const char *old=win_acxml_attr(attributes,n,"oldVersion"),*replacement=win_acxml_attr(attributes,n,"newVersion");char left[0x40];const char *dash;win_actctx_redirect *r;
            dep=stack[depth-1u].dependency;if(!doc->dependencies[dep].has_identity||!old||!replacement||doc->redirect_count==WIN_ACTCTX_ASSEMBLIES)ACXML_FAIL(14001);
            r=&doc->redirects[doc->redirect_count++];r->dependency=(uint16_t)dep;dash=strchr(old,'-');
            if(dash){size_t k=(size_t)(dash-old);if(k>=sizeof(left))ACXML_FAIL(14001);memcpy(left,old,k);left[k]=0;if(!win_acxml_version(left,&r->low)||!win_acxml_version(dash+1u,&r->high))ACXML_FAIL(14001);}
            else{if(!win_acxml_version(old,&r->low))ACXML_FAIL(14001);r->high=r->low;}
            if(r->low>r->high||!win_acxml_version(replacement,&r->replacement))ACXML_FAIL(14001);
            role=ACXML_REDIRECT;
        }else if(!strcmp(local,"file")&&stack[depth-1u].role==ACXML_ASSEMBLY&&!doc->policy){
            const char *v=win_acxml_attr(attributes,n,"name"),*hash,*alg;win_actctx_xml_file *file;
            if(!v||!win_acxml_ascii(v)||!win_acxml_safe_leaf(v)||doc->file_count==WIN_ACTCTX_FILES)ACXML_FAIL(14001);
            for(i=0;i<doc->file_count;++i)if(win_acxml_equal(doc->files[i].name,v))ACXML_FAIL(14001);
            file=&doc->files[doc->file_count++];if(!win_acxml_copy(file->name,sizeof(file->name),v))ACXML_FAIL(50);
            hash=win_acxml_attr(attributes,n,"hash");alg=win_acxml_attr(attributes,n,"hashalg");
            if((hash&&!win_acxml_copy(file->hash,sizeof(file->hash),hash))||(alg&&!win_acxml_copy(file->hashalg,sizeof(file->hashalg),alg)))ACXML_FAIL(50);
            for(i=0;i<n;++i)if(!win_acxml_is_xmlns(attributes[i].name)&&strcmp(attributes[i].name,"name")&&strcmp(attributes[i].name,"hash")&&strcmp(attributes[i].name,"hashalg"))ACXML_FAIL(50);
            role=ACXML_FILE;
        }else if(!strcmp(local,"description")&&stack[depth-1u].role==ACXML_ASSEMBLY)role=ACXML_METADATA;
        else if(!strcmp(local,"noInheritable")&&stack[depth-1u].role==ACXML_ASSEMBLY){if(doc->no_inheritable)ACXML_FAIL(14001);doc->no_inheritable=1u;role=ACXML_NOINHERITABLE;}
        else ACXML_FAIL(50);
        if(role==ACXML_ASSEMBLY||role==ACXML_DEPENDENCY||role==ACXML_DEPENDENT||role==ACXML_REDIRECT||role==ACXML_NOINHERITABLE){
            for(i=0;i<n;++i){
                if(win_acxml_is_xmlns(attributes[i].name))continue;
                if(role==ACXML_ASSEMBLY&&!strcmp(attributes[i].name,"manifestVersion"))continue;
                if(role==ACXML_REDIRECT&&(!strcmp(attributes[i].name,"oldVersion")||!strcmp(attributes[i].name,"newVersion")))continue;
                ACXML_FAIL(50);
            }
        }
        if(!win_acxml_copy(stack[depth].name,sizeof(stack[depth].name),name))ACXML_FAIL(14001);
        stack[depth].ns_before=ns_before;stack[depth].role=role;stack[depth].dependency=dep;
        if(empty){ns_count=ns_before;if(!depth)root_closed=1u;}else ++depth;
    }
    if(depth||!root_seen||!root_closed||(!application&&!doc->has_identity))ACXML_FAIL(14001);
    if(application&&doc->policy)ACXML_FAIL(14001);
    {unsigned dependency;for(dependency=0;dependency<doc->dependency_count;++dependency)if(!doc->dependencies[dependency].has_identity)ACXML_FAIL(14001);}
    if(doc->policy&&(!doc->redirect_count||doc->file_count||doc->no_inheritable))ACXML_FAIL(14001);
done:
    free(attributes);free(text);return error;
#undef ACXML_FAIL
}
