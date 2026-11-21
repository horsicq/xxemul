/* Bounded thread activation stacks and Win32 assembly binding. Host records are authoritative;
 * guest section storage follows the pinned Wine compatibility representation. */
typedef struct win_actctx_file {
    char name[0x30], guest[WIN_ACTCTX_PATH];
    uint32_t roster, data_offset;
} win_actctx_file;
typedef struct win_actctx_assembly {
    win_actctx_identity identity;
    char manifest[WIN_ACTCTX_PATH], directory[WIN_ACTCTX_PATH], policy[WIN_ACTCTX_PATH];
    uint8_t visiting;
} win_actctx_assembly;
struct win_actctx_state {
    win_actctx_assembly assemblies[WIN_ACTCTX_ASSEMBLIES];
    win_actctx_file files[WIN_ACTCTX_FILES];
    uint64_t section, handle;
    uint32_t section_size, references;
    uint16_t assembly_count, file_count;
    uint8_t ready;
};
typedef struct win_actctx_store_entry {
    win_actctx_document *document;
    char manifest[WIN_ACTCTX_PATH], directory[WIN_ACTCTX_PATH];
} win_actctx_store_entry;
typedef struct win_actctx_builder {
    xxemul_windows *process;
    win_actctx_state *context;
    win_actctx_store_entry store[WIN_ACTCTX_STORE];
    unsigned store_count;
} win_actctx_builder;

static int win_actctx_identity_match(const win_actctx_identity *a,const win_actctx_identity *b,int version)
{
    return !strcmp(a->type,b->type)&&win_acxml_equal(a->name,b->name)&&win_acxml_equal(a->arch,b->arch)&&
        win_acxml_equal(a->token,b->token)&&win_acxml_equal(a->language,b->language)&&
        (!version||(a->has_version&&b->has_version&&a->version==b->version));
}
static int win_actctx_arch(xxemul_windows *p,win_actctx_identity *id)
{
    const char *arch=win_word_size(p->emulator)==8u?"amd64":"x86";
    if(!id->arch[0]||!strcmp(id->arch,"*"))return win_acxml_copy(id->arch,sizeof(id->arch),arch)?0:14001;
    return win_acxml_equal(id->arch,arch)?0:14001;
}
static int win_actctx_key_name(const char *input,char *key,size_t capacity)
{
    const char *base=input,*at;size_t n,i;
    if(!input||!*input)return 0;
    for(at=input;*at;++at)if(*at=='/'||*at=='\\')base=at+1u;
    if(!win_acxml_ascii(base)||!win_acxml_safe_leaf(base)||!win_acxml_copy(key,capacity,base))return 0;
    n=strlen(key);if(!strchr(key,'.')){if(n+5u>capacity)return 0;memcpy(key+n,".dll",5u);}
    for(i=0u;key[i];++i)key[i]=(char)tolower((unsigned char)key[i]);
    return 1;
}
static win_actctx_state *win_actctx_object(const xxemul_windows *p,uint64_t handle);
static win_actctx_state *win_actctx_active(const xxemul_windows *p)
{
    const win_thread_context *thread=&p->threads[p->thread_current];
    return thread->actctx_depth?win_actctx_object(p,thread->actctx_handles[thread->actctx_depth-1u]):NULL;
}
static win_actctx_file *win_actctx_lookup(const xxemul_windows *p,const char *key,win_actctx_state **owner)
{
    win_actctx_state *contexts[2]={win_actctx_active(p),p->actctx};unsigned n,i;
    /* Only the active frame participates. A NULL frame therefore selects the
       process defaults rather than exposing lower explicit activations. */
    for(n=0u;n<2u;++n){
        win_actctx_state *c=contexts[n];if(!c||!c->ready)continue;
        for(i=0u;i<c->file_count;++i)if(win_acxml_equal(key,c->files[i].name)){
            if(owner)*owner=c;
            return &c->files[i];
        }
    }
    return NULL;
}
static win_actctx_file *win_actctx_find_file(const xxemul_windows *p,const char *name)
{
    char key[0x30];
    return win_actctx_key_name(name,key,sizeof(key))?win_actctx_lookup(p,key,NULL):NULL;
}
static int win_actctx_selected(const xxemul_windows *p,const char *name)
{return p&&win_actctx_find_file(p,name)!=NULL;}
static int win_actctx_host_path(xxemul_windows *p,const char *name,char *host,size_t capacity)
{
    win_actctx_file *file=win_actctx_find_file(p,name);char requested[0x800];
    if(!file)return 0;
    if(strpbrk(name,"/\\")){
        char selected[0x800];
        if(!win_guest_path(p,name,requested,sizeof(requested))||!win_guest_path(p,file->guest,selected,sizeof(selected))||!win_acxml_equal(requested,selected)){
            p->last_error=14001u;return -1;
        }
    }
    if(!win_dll_host_path(p,file->guest,host,capacity)){p->last_error=126u;return -1;}
    return 1;
}
static int win_actctx_read_document(xxemul_windows *p,const char *guest,win_actctx_document **out)
{
    char host[0x800];FILE *stream;long length;uint8_t *raw;win_actctx_document *doc;int error;
    *out=NULL;if(!win_dll_host_path(p,guest,host,sizeof(host)))return 14001;
    stream=fopen(host,"rb");if(!stream)return 14001;
    if(fseek(stream,0,SEEK_END)||((length=ftell(stream))<=0)||length>WIN_ACTCTX_XML_MAX||fseek(stream,0,SEEK_SET)){fclose(stream);return 14001;}
    raw=(uint8_t*)malloc((size_t)length);doc=(win_actctx_document*)calloc(1,sizeof(*doc));
    if(!raw||!doc){free(raw);free(doc);fclose(stream);return 8;}
    if(fread(raw,1,(size_t)length,stream)!=(size_t)length){free(raw);free(doc);fclose(stream);return 14001;}
    fclose(stream);error=win_actctx_parse_xml(raw,(size_t)length,doc,0);free(raw);
    if(error){free(doc);return error;}*out=doc;return 0;
}
static int win_actctx_store_add(win_actctx_builder *b,const char *leaf)
{
    win_actctx_store_entry *entry;size_t n=strlen(leaf);unsigned i;int error;char stem[0x100];
    if(n<10u||!win_acxml_equal(leaf+n-9u,".manifest"))return 0;
    if(!win_acxml_safe_leaf(leaf)||n>=0x100u)return 50;
    memcpy(stem,leaf,n-9u);stem[n-9u]=0;
    if(!win_acxml_safe_leaf(stem))return 14001;
    if(b->store_count==WIN_ACTCTX_STORE)return 50;
    entry=&b->store[b->store_count];
    if(snprintf(entry->manifest,sizeof(entry->manifest),"C:\\Windows\\WinSxS\\Manifests\\%s",leaf)>=(int)sizeof(entry->manifest))return 50;
    if(snprintf(entry->directory,sizeof(entry->directory),"C:\\Windows\\WinSxS\\%.*s\\",(int)(n-9u),leaf)>=(int)sizeof(entry->directory))return 50;
    error=win_actctx_read_document(b->process,entry->manifest,&entry->document);if(error)return error;
    /* Other machine identities remain visible to uniqueness checks, but cannot
       satisfy a dependency for this process. No version is inferred from a name. */
    for(i=0u;i<b->store_count;++i)
        if(win_actctx_identity_match(&entry->document->identity,&b->store[i].document->identity,1)){
            free(entry->document);entry->document=NULL;return 14001;
        }
    ++b->store_count;return 0;
}
static int win_actctx_scan_store(win_actctx_builder *b)
{
    char host[0x800];int error=0;
    if(!win_guest_path(b->process,"C:\\Windows\\WinSxS\\Manifests",host,sizeof(host)))return 14001;
#if defined(_WIN32)
    {
        WIN32_FIND_DATAA data;HANDLE search;char pattern[0x820];
        if(snprintf(pattern,sizeof(pattern),"%s\\*",host)>=(int)sizeof(pattern))return 50;
        search=FindFirstFileA(pattern,&data);
        if(search==INVALID_HANDLE_VALUE){DWORD code=GetLastError();return code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND?0:14001;}
        do{
            if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)continue;
            if(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){error=14001;break;}
            error=win_actctx_store_add(b,data.cFileName);if(error)break;
        }while(FindNextFileA(search,&data));
        FindClose(search);
    }
#else
    {
        DIR *directory=opendir(host);struct dirent *item;
        if(!directory)return errno==ENOENT?0:14001;
        while((item=readdir(directory))!=NULL){
            if(!strcmp(item->d_name,".")||!strcmp(item->d_name,".."))continue;
            error=win_actctx_store_add(b,item->d_name);if(error)break;
        }
        closedir(directory);
    }
#endif
    return error;
}
static int win_actctx_add_files(win_actctx_builder *b,const win_actctx_document *doc,unsigned roster,const char *directory)
{
    unsigned i,j;win_actctx_state *c=b->context;
    for(i=0u;i<doc->file_count;++i){
        win_actctx_file *file;
        if(c->file_count==WIN_ACTCTX_FILES)return 50;
        for(j=0u;j<c->file_count;++j)if(win_acxml_equal(c->files[j].name,doc->files[i].name))return 14001;
        /* A roster must not silently replace an already committed immutable
           modeled system module. General known-DLL redirection is not claimed. */
        for(j=0u;j<b->process->module_count;++j)
            if(b->process->modules[j].live&&!b->process->modules[j].real&&win_acxml_equal(b->process->modules[j].name,doc->files[i].name))return 50;
        file=&c->files[c->file_count];
        if(!win_acxml_copy(file->name,sizeof(file->name),doc->files[i].name)||
           snprintf(file->guest,sizeof(file->guest),"%s%s",directory,doc->files[i].name)>=(int)sizeof(file->guest))return 50;
        file->roster=roster;++c->file_count;
    }
    return 0;
}
static int win_actctx_resolve_dependency(win_actctx_builder *b,const win_actctx_identity *requested)
{
    win_actctx_identity wanted=*requested;win_actctx_store_entry *selected=NULL,*policy=NULL;
    unsigned i,j,applicable=0u,slot;int error;uint64_t replacement=wanted.version;char policy_name[0x80];
    if(!wanted.has_version||strcmp(wanted.type,"win32"))return 14001;
    if((error=win_actctx_arch(b->process,&wanted))!=0)return error;
    if(snprintf(policy_name,sizeof(policy_name),"policy.%u.%u.%s",(unsigned)(wanted.version>>48),(unsigned)((wanted.version>>32)&0xffffu),wanted.name)>=(int)sizeof(policy_name))return 50;
    for(i=0u;i<b->store_count;++i){
        win_actctx_document *doc=b->store[i].document;win_actctx_identity id=doc->identity;
        if(!doc->policy||!win_acxml_equal(id.name,policy_name)||!win_acxml_equal(id.token,wanted.token)||!win_acxml_equal(id.language,wanted.language))continue;
        if(win_actctx_arch(b->process,&id)||!win_acxml_equal(id.arch,wanted.arch))continue;
        if(!id.token[0]||(id.version>>32)!=(wanted.version>>32))return 50;
        for(j=0u;j<doc->redirect_count;++j){
            win_actctx_redirect *r=&doc->redirects[j];win_actctx_identity dep=doc->dependencies[r->dependency].identity;
            if(win_actctx_arch(b->process,&dep)||!win_actctx_identity_match(&wanted,&dep,0))continue;
            if(dep.has_version&&dep.version!=wanted.version)continue;
            if(wanted.version<r->low||wanted.version>r->high)continue;
            if((r->low>>32)!=(wanted.version>>32)||(r->high>>32)!=(wanted.version>>32)||(r->replacement>>32)!=(wanted.version>>32))return 50;
            if(++applicable!=1u)return 14001;
            replacement=r->replacement;policy=&b->store[i];
        }
    }
    wanted.version=replacement;
    for(i=0u;i<b->context->assembly_count;++i){
        win_actctx_assembly *a=&b->context->assemblies[i];
        if(win_actctx_identity_match(&wanted,&a->identity,1))return a->visiting?14001:0;
    }
    for(i=0u;i<b->store_count;++i){
        win_actctx_document *doc=b->store[i].document;win_actctx_identity id=doc->identity;
        if(doc->policy||win_actctx_arch(b->process,&id)||!win_actctx_identity_match(&wanted,&id,1))continue;
        if(selected)return 14001;
        selected=&b->store[i];
    }
    if(!selected)return 14001;
    if(b->context->assembly_count==WIN_ACTCTX_ASSEMBLIES)return 50;
    slot=b->context->assembly_count++;
    b->context->assemblies[slot].identity=wanted;b->context->assemblies[slot].visiting=1u;
    if(!win_acxml_copy(b->context->assemblies[slot].manifest,WIN_ACTCTX_PATH,selected->manifest)||
       !win_acxml_copy(b->context->assemblies[slot].directory,WIN_ACTCTX_PATH,selected->directory)||
       (policy&&!win_acxml_copy(b->context->assemblies[slot].policy,WIN_ACTCTX_PATH,policy->manifest)))return 50;
    if((error=win_actctx_add_files(b,selected->document,slot+1u,selected->directory))!=0)return error;
    for(i=0u;i<selected->document->dependency_count;++i)
        if((error=win_actctx_resolve_dependency(b,&selected->document->dependencies[i].identity))!=0)return error;
    b->context->assemblies[slot].visiting=0u;return 0;
}

static int win_actctx_resource_span(xxemul_windows *p,uint32_t offset,uint32_t count,const uint8_t **bytes)
{
    if(offset>p->resource_size||count>p->resource_size-offset||p->resource_rva>p->image_size||
       offset>p->image_size-p->resource_rva||count>p->image_size-p->resource_rva-offset)return 0;
    *bytes=p->emulator->region_data+p->resource_rva+offset;return 1;
}
static int win_actctx_resource_child(xxemul_windows *p,uint32_t directory,uint32_t id,uint32_t *child,int *found)
{
    const uint8_t *raw;uint32_t count,i;*found=0;
    if(!win_actctx_resource_span(p,directory,0x10u,&raw))return 14001;
    count=(uint32_t)win_le16(raw+12u)+win_le16(raw+14u);if(count>0x100u)return 50;
    if(directory>UINT32_MAX-0x10u||!win_actctx_resource_span(p,directory+0x10u,count*8u,&raw))return 14001;
    for(i=0u;i<count;++i){
        uint32_t name=win_le32(raw+i*8u),target=win_le32(raw+i*8u+4u);
        if(name!=id)continue;
        if(*found)return 14001;
        if(!(target&0x80000000u))return 14001;
        *child=target&0x7fffffffu;*found=1;
    }
    return 0;
}
static int win_actctx_file_backed(xxemul_windows *p,uint32_t rva,uint32_t size)
{
    const uint8_t *image=p->emulator->region_data;uint32_t nt=win_le32(image+0x3cu),table;unsigned count,i,matches=0;
    if(nt>p->image_size||24u>p->image_size-nt)return 0;
    count=win_le16(image+nt+6u);table=nt+24u;
    if(win_le16(image+nt+20u)>p->image_size-table)return 0;
    table+=win_le16(image+nt+20u);
    if(!count||count>96u||table>p->image_size||count*40u>p->image_size-table)return 0;
    for(i=0u;i<count;++i){
        const uint8_t *s=image+table+i*40u;uint32_t va=win_le32(s+12u),raw=win_le32(s+16u);
        if(rva>=va&&rva-va<=raw&&size<=raw-(rva-va))++matches;
    }
    return matches==1u&&rva<=p->image_size&&size<=p->image_size-rva;
}
static int win_actctx_main_manifest(xxemul_windows *p,const uint8_t **xml,uint32_t *size,int *found)
{
    uint32_t type=0,name=0,language=0,count,i,data_offset=0;const uint8_t *raw;int present,error;
    *found=0;*xml=NULL;*size=0;
    if(!p->resource_rva&&!p->resource_size)return 0;
    if(!p->resource_rva||!p->resource_size)return 14001;
    if((error=win_actctx_resource_child(p,0u,24u,&type,&present))!=0)return error;
    if(!present)return 0;
    if((error=win_actctx_resource_child(p,type,1u,&name,&present))!=0)return error;
    if(!present)return 0;
    if(!win_actctx_resource_span(p,name,0x10u,&raw))return 14001;
    count=(uint32_t)win_le16(raw+12u)+win_le16(raw+14u);if(!count||count>0x100u)return 14001;
    if(name>UINT32_MAX-0x10u||!win_actctx_resource_span(p,name+0x10u,count*8u,&raw))return 14001;
    for(i=0u;i<count;++i){
        uint32_t entry_name=win_le32(raw+i*8u),target=win_le32(raw+i*8u+4u);
        if((entry_name&0x80000000u)||(target&0x80000000u))return 14001;
        if(i&&target!=data_offset)return 50; /* No guessed language fallback. */
        data_offset=target;language=entry_name;
    }
    (void)language;
    if(!win_actctx_resource_span(p,data_offset,0x10u,&raw))return 14001;
    *size=win_le32(raw+4u);
    if(!*size||*size>WIN_ACTCTX_XML_MAX||!win_actctx_file_backed(p,win_le32(raw),*size))return 14001;
    *xml=p->emulator->region_data+win_le32(raw);*found=1;return 0;
}
static uint32_t win_actctx_align4(uint32_t n){return (n+3u)&~UINT32_C(3);}
static void win_actctx_utf16(uint8_t *to,const char *text)
{size_t i;for(i=0u;text[i];++i)win_put16(to+i*2u,(uint8_t)text[i]);}
static uint32_t win_actctx_hash(const char *text)
{uint32_t value=0;for(;*text;++text)value=value*UINT32_C(0x1003f)+(uint8_t)toupper((unsigned char)*text);return value;}
static int win_actctx_build_section(xxemul_windows *p,win_actctx_state *c)
{
    uint32_t total=44u+c->file_count*24u,cursor;unsigned i;uint8_t *raw;win_allocation *allocation;
    for(i=0u;i<c->file_count;++i){
        total+=win_actctx_align4((uint32_t)(strlen(c->files[i].name)+1u)*2u)+28u+
            win_actctx_align4((uint32_t)strlen(c->files[i].guest)*2u);
    }
    total=(total+15u)&~UINT32_C(15);if(total>WIN_MAX_IO)return 50;
    raw=(uint8_t*)calloc(1,total);if(!raw)return 8;
    win_put32(raw,0x64487353u);win_put32(raw+4u,44u);win_put32(raw+20u,c->file_count);win_put32(raw+24u,44u);
    cursor=44u+c->file_count*24u;
    for(i=0u;i<c->file_count;++i){
        win_actctx_file *file=&c->files[i];uint8_t *index=raw+44u+i*24u,*data;uint32_t name_bytes=(uint32_t)strlen(file->name)*2u,path_bytes=(uint32_t)strlen(file->guest)*2u;
        win_put32(index,win_actctx_hash(file->name));win_put32(index+4u,cursor);win_put32(index+8u,name_bytes);
        win_actctx_utf16(raw+cursor,file->name);cursor+=win_actctx_align4(name_bytes+2u);
        file->data_offset=cursor;win_put32(index+12u,cursor);
        win_put32(index+16u,20u); /* Wine raw index describes the base record. */
        win_put32(index+20u,file->roster);data=raw+cursor;
        win_put32(data,28u);win_put32(data+4u,0u);win_put32(data+8u,win_actctx_align4(path_bytes));win_put32(data+12u,1u);win_put32(data+16u,cursor+20u);
        win_put32(data+20u,path_bytes);win_put32(data+24u,cursor+28u);win_actctx_utf16(data+28u,file->guest);
        cursor+=28u+win_actctx_align4(path_bytes);
    }
    if(cursor>total){free(raw);return 14001;}
    c->section=win_heap_alloc(p,total);c->handle=win_heap_alloc(p,0x10u);
    if(!c->section||!c->handle){free(raw);return 8;}
    allocation=win_find_allocation(p,c->section);if(!allocation){free(raw);return 8;}allocation->heap_owner=UINT64_MAX;
    allocation=win_find_allocation(p,c->handle);if(!allocation){free(raw);return 8;}allocation->heap_owner=UINT64_MAX;
    if(!win_write(p,c->section,raw,total)){free(raw);return 14001;}
    free(raw);c->section_size=total;c->references=1u;c->ready=1u;return 0;
}
static void win_actctx_drop(xxemul_windows *p,win_actctx_state *c)
{
    win_allocation *allocation;
    if(!c)return;
    if(c->section&&(allocation=win_find_allocation(p,c->section))!=NULL)allocation->active=0u;
    if(c->handle&&(allocation=win_find_allocation(p,c->handle))!=NULL)allocation->active=0u;
    free(c);
}
static void win_actctx_destroy(xxemul_windows *p)
{
    unsigned i;
    for(i=0u;i<WIN_MAX_THREADS;++i)if(p->threads[i].id)win_actctx_abandon_thread(p,p->threads[i].id);
    win_actctx_drop(p,p->actctx);p->actctx=NULL;
    for(i=0u;i<sizeof(p->actctx_created)/sizeof(p->actctx_created[0]);++i){
        win_actctx_drop(p,p->actctx_created[i]);p->actctx_created[i]=NULL;
    }
}
static int win_actctx_make(xxemul_windows *p,const uint8_t *xml,uint32_t size,const char *directory,win_actctx_state **out)
{
    win_actctx_builder *builder=NULL;win_actctx_document *main_doc=NULL;win_actctx_state *c=NULL;int error=8;unsigned i;
    *out=NULL;
    main_doc=(win_actctx_document*)calloc(1,sizeof(*main_doc));builder=(win_actctx_builder*)calloc(1,sizeof(*builder));
    c=(win_actctx_state*)calloc(1,sizeof(*c));
    if(!main_doc||!builder||!c)goto done;
    if((error=win_actctx_parse_xml(xml,size,main_doc,1))!=0)goto done;
    builder->process=p;builder->context=c;c->assembly_count=1u;c->assemblies[0].identity=main_doc->identity;
    if(!win_acxml_copy(c->assemblies[0].directory,WIN_ACTCTX_PATH,directory)){error=50;goto done;}
    if((error=win_actctx_add_files(builder,main_doc,1u,directory))!=0)goto done;
    if(main_doc->dependency_count&&(error=win_actctx_scan_store(builder))!=0)goto done;
    for(i=0u;i<main_doc->dependency_count;++i)
        if((error=win_actctx_resolve_dependency(builder,&main_doc->dependencies[i].identity))!=0)goto done;
    error=win_actctx_build_section(p,c);
    if(!error){*out=c;c=NULL;}
done:
    if(builder){for(i=0u;i<builder->store_count;++i)free(builder->store[i].document);free(builder);}
    free(main_doc);win_actctx_drop(p,c);return error;
}
static int win_actctx_prepare(xxemul_windows *p)
{
    const uint8_t *xml;uint32_t size;int found,error;
    /* Disabled profile performs no resource or filesystem probe. */
    if(!p->emulator->windows_default_actctx)return 0;
    if(p->image_is_dll||p->emulator->arch!=XXEMUL_ARCH_X86)return 50;
    if((error=win_actctx_main_manifest(p,&xml,&size,&found))!=0||!found)return error;
    return win_actctx_make(p,xml,size,"C:\\",&p->actctx);
}
static win_actctx_state *win_actctx_object(const xxemul_windows *p,uint64_t handle)
{
    unsigned i;
    if(p->actctx&&p->actctx->handle==handle)return p->actctx;
    for(i=0u;i<sizeof(p->actctx_created)/sizeof(p->actctx_created[0]);++i)
        if(p->actctx_created[i]&&p->actctx_created[i]->handle==handle)return p->actctx_created[i];
    return NULL;
}
static void win_actctx_unref(xxemul_windows *p,win_actctx_state *c)
{
    unsigned slot;
    if(!c||!c->references||(c==p->actctx&&c->references<=1u))return;
    if(--c->references)return;
    for(slot=0u;slot<sizeof(p->actctx_created)/sizeof(p->actctx_created[0]);++slot)
        if(p->actctx_created[slot]==c){p->actctx_created[slot]=NULL;break;}
    win_actctx_drop(p,c);
}
static void win_actctx_abandon_thread(xxemul_windows *p,uint32_t owner)
{
    unsigned i;
    for(i=0u;i<WIN_MAX_THREADS;++i){
        win_thread_context *thread=&p->threads[i];if(thread->id!=owner)continue;
        while(thread->actctx_depth){
            size_t slot=--thread->actctx_depth;uint64_t handle=thread->actctx_handles[slot];
            thread->actctx_handles[slot]=thread->actctx_cookies[slot]=0u;
            win_actctx_unref(p,win_actctx_object(p,handle));
        }
        return;
    }
}
static xxemul_status win_actctx_ansi_source(xxemul_windows *p,uint64_t source)
{
    uint64_t cursor=source,limit=win_word_size(p->emulator)==4u?UINT32_MAX:UINT64_MAX;
    size_t unit;
    if(!cursor)return XXEMUL_STATUS_OK;
    /* ACP1252 is single-byte. Validate the optional A source through NUL;
     * the supported module/resource form does not retain or select by it. */
    for(unit=0u;unit<0x10000u;++unit){
        uint64_t character;
        if(!win_load(p,cursor,1u,&character))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(!character)return XXEMUL_STATUS_OK;
        if(cursor>=limit)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        ++cursor;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}
static xxemul_status win_actctx_create(xxemul_windows *p,uint64_t pointer,int ansi,uint64_t *result)
{
    uint8_t width=win_word_size(p->emulator),raw[0x38];uint64_t cb,module,resource,address;uint32_t flags,entry,size,saved_error=p->last_error;
    win_resource_key type_key,name_key;win_resource_image image;win_module *loaded;win_actctx_state *c=NULL;uint8_t *xml=NULL;char directory[WIN_ACTCTX_PATH],*tail;unsigned slot;int error;
    *result=width==8u?UINT64_MAX:UINT32_MAX;
    if(!pointer){p->last_error=87u;return XXEMUL_STATUS_OK;}
    if(!win_load(p,pointer,4u,&cb))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(cb!=(width==8u?0x38u:0x20u)){p->last_error=87u;return XXEMUL_STATUS_OK;}
    if(!win_read(p,pointer,raw,(size_t)cb))return XXEMUL_STATUS_ADDRESS_FAULT;
    flags=win_le32(raw+4u);
    if(flags&~UINT32_C(0xff)){p->last_error=87u;return XXEMUL_STATUS_OK;}
    if(flags!=0x88u)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(ansi){
        uint64_t source=width==8u?win_le64(raw+8u):win_le32(raw+8u);
        xxemul_status status=win_actctx_ansi_source(p,source);
        if(status!=XXEMUL_STATUS_OK)return status;
    }
    resource=width==8u?win_le64(raw+0x20u):win_le32(raw+0x14u);
    module=width==8u?win_le64(raw+0x30u):win_le32(raw+0x1cu);
    if(!resource){p->last_error=87u;return XXEMUL_STATUS_OK;}
    if(resource>UINT16_MAX)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    loaded=win_dll_at(p,module);
    if(!module||(module!=p->image_base&&(!loaded||!loaded->real))){p->last_error=6u;return XXEMUL_STATUS_OK;}
    memset(&type_key,0,sizeof(type_key));memset(&name_key,0,sizeof(name_key));type_key.id=24u;name_key.id=(uint16_t)resource;
    if(!win_resource_lookup(p,module,&type_key,&name_key,0,0u,&image,&entry,&address,&size)){
        if(p->emulator->fault_address_valid&&p->emulator->windows_exception_code==0xc0000005u)return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if(!size){p->last_error=14001u;return XXEMUL_STATUS_OK;}
    if(size>WIN_ACTCTX_XML_MAX)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    xml=(uint8_t*)malloc(size);if(!xml){p->last_error=8u;return XXEMUL_STATUS_OK;}
    if(!win_read(p,address,xml,size)){free(xml);return XXEMUL_STATUS_ADDRESS_FAULT;}
    if(module==p->image_base){if(!win_guest_program_path(p,directory,sizeof(directory))){free(xml);p->last_error=206u;return XXEMUL_STATUS_OK;}}
    else if(!win_loader_module_path(p,loaded,directory,sizeof(directory))){free(xml);p->last_error=206u;return XXEMUL_STATUS_OK;}
    tail=strrchr(directory,'\\');if(!tail){free(xml);p->last_error=14001u;return XXEMUL_STATUS_OK;}tail[1]=0;
    for(slot=0u;slot<sizeof(p->actctx_created)/sizeof(p->actctx_created[0]);++slot)if(!p->actctx_created[slot])break;
    if(slot==sizeof(p->actctx_created)/sizeof(p->actctx_created[0])){free(xml);p->last_error=8u;return XXEMUL_STATUS_OK;}
    error=win_actctx_make(p,xml,size,directory,&c);free(xml);
    if(error){
        if(p->emulator->fault_address_valid&&p->emulator->windows_exception_code==0xc0000005u)return XXEMUL_STATUS_ADDRESS_FAULT;
        if(error==50)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        p->last_error=(uint32_t)error;return XXEMUL_STATUS_OK;
    }
    p->actctx_created[slot]=c;*result=c->handle;p->last_error=saved_error;return XXEMUL_STATUS_OK;
}

static int win_actctx_api_name(const char *name)
{
    return !strcmp(name,"FindActCtxSectionStringA")||!strcmp(name,"FindActCtxSectionStringW")||
        !strcmp(name,"GetCurrentActCtx")||!strcmp(name,"AddRefActCtx")||!strcmp(name,"ReleaseActCtx")||
        !strcmp(name,"ActivateActCtx")||!strcmp(name,"DeactivateActCtx");
}
static int win_actctx_unsupported_name(const char *name)
{
    return !strcmp(name,"CreateActCtxA")||!strcmp(name,"CreateActCtxW")||!strcmp(name,"QueryActCtxA")||!strcmp(name,"QueryActCtxW")||
        !strcmp(name,"QueryActCtxSettingsW")||!strcmp(name,"ZombifyActCtx")||!strcmp(name,"FindActCtxSectionGuid");
}
static xxemul_status win_actctx_key(xxemul_windows *p,uint64_t address,int wide,char *key,int *fits)
{
    unsigned i;*fits=1;
    for(i=0u;i<0x1000u;++i){
        uint64_t ch;if(!win_load(p,address+(uint64_t)i*(wide?2u:1u),wide?2u:1u,&ch))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(!ch){if(i<0x30u)key[i]=0;else *fits=0;return XXEMUL_STATUS_OK;}
        if(ch>0x7fu)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(i+1u<0x30u)key[i]=(char)ch;else *fits=0;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}
static int win_actctx_output(xxemul_windows *p,uint64_t address,size_t size)
{
    if(win_memory_span(p,address,size)&&xxemul_windows_memory_access(p,address,size,1u,1))return 1;
    win_guest_memory_fault(p,address,size,1u);return 0;
}
static xxemul_status win_actctx_api(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result)
{
    win_actctx_state *c=p->actctx;uint8_t width=win_word_size(p->emulator);uint8_t bytes[0x70]={0};
    *result=0;
    if(p->emulator->arch!=XXEMUL_ARCH_X86)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(!strcmp(name,"CreateActCtxA")||!strcmp(name,"CreateActCtxW"))
        return win_actctx_create(p,arg[0],!strcmp(name,"CreateActCtxA"),result);
    if(!strcmp(name,"ActivateActCtx")){
        win_thread_context *thread=&p->threads[p->thread_current];uint64_t cookie;
        c=arg[0]?win_actctx_object(p,arg[0]):NULL;
        if(arg[0]&&!c){p->last_error=87u;return XXEMUL_STATUS_OK;}
        if(thread->actctx_depth>=sizeof(thread->actctx_handles)/sizeof(thread->actctx_handles[0])||
           p->actctx_next_cookie>=(width==8u?UINT64_MAX:UINT32_MAX)||
           (c&&c->references==UINT32_MAX))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!win_actctx_output(p,arg[1],width))return XXEMUL_STATUS_ADDRESS_FAULT;
        cookie=p->actctx_next_cookie+1u;
        if(!win_store(p,arg[1],width,cookie))return XXEMUL_STATUS_ADDRESS_FAULT;
        thread->actctx_handles[thread->actctx_depth]=arg[0];
        thread->actctx_cookies[thread->actctx_depth++]=cookie;p->actctx_next_cookie=cookie;
        if(c)++c->references;
        *result=1u;return XXEMUL_STATUS_OK;
    }
    if(!strcmp(name,"DeactivateActCtx")){
        win_thread_context *thread=&p->threads[p->thread_current];size_t slot;
        if((uint32_t)arg[0]&~1u){p->last_error=87u;return XXEMUL_STATUS_OK;}
        /* Early/invalid deactivation raises Windows exceptions. Until their
           exception continuations are admitted, stop before changing state. */
        if((uint32_t)arg[0]||!thread->actctx_depth||thread->actctx_cookies[thread->actctx_depth-1u]!=arg[1])
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        slot=--thread->actctx_depth;c=win_actctx_object(p,thread->actctx_handles[slot]);
        thread->actctx_handles[slot]=thread->actctx_cookies[slot]=0u;
        win_actctx_unref(p,c);*result=1u;return XXEMUL_STATUS_OK;
    }
    if(!strcmp(name,"GetCurrentActCtx")){
        if(!arg[0]){p->last_error=87u;return XXEMUL_STATUS_OK;}
        c=win_actctx_active(p);
        if(c&&c->references==UINT32_MAX)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!win_actctx_output(p,arg[0],width))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(!win_store(p,arg[0],width,c?c->handle:0u))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(c)++c->references;
        *result=1u;return XXEMUL_STATUS_OK;
    }
    if(!strcmp(name,"AddRefActCtx")||!strcmp(name,"ReleaseActCtx")){
        /* Pinned Wine check_actctx explicitly recognizes these no-object
           sentinels; they do not acquire or release the process anchor. */
        if(!arg[0]||arg[0]==(width==8u?UINT64_MAX:UINT32_MAX))return XXEMUL_STATUS_OK;
        c=win_actctx_object(p,arg[0]);
        if(!c)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!strcmp(name,"AddRefActCtx")){
            if(c->references==UINT32_MAX)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            ++c->references;
        }else{
            if(c==p->actctx&&c->references<=1u)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            win_actctx_unref(p,c);
        }
        return XXEMUL_STATUS_OK;
    }
    {
        uint32_t flags=(uint32_t)arg[0],section=(uint32_t)arg[2];uint64_t cbsize;int fits;
        char key[0x30]={0};win_actctx_file *file=NULL;xxemul_status status;
        if((flags&~7u)||arg[1]||!arg[3]||!arg[4]||!section||section>12u){p->last_error=87u;return XXEMUL_STATUS_OK;}
        if((flags&6u)||section!=2u)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!win_load(p,arg[4],4u,&cbsize))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(cbsize!=(width==8u?0x70u:0x40u)){p->last_error=87u;return XXEMUL_STATUS_OK;}
        status=win_actctx_key(p,arg[3],win_suffix(name,"W"),key,&fits);if(status!=XXEMUL_STATUS_OK)return status;
        if(fits)file=win_actctx_lookup(p,key,&c);
        if(!file){p->last_error=14007u;return XXEMUL_STATUS_OK;}
        if(!win_actctx_output(p,arg[4],(size_t)cbsize))return XXEMUL_STATUS_ADDRESS_FAULT;
        if((flags&1u)&&c->references==UINT32_MAX){p->last_error=8u;return XXEMUL_STATUS_OK;}
        win_put32(bytes,(uint32_t)cbsize);win_put32(bytes+4u,1u);
        if(width==8u){
            win_put64(bytes+8u,c->section+file->data_offset);win_put32(bytes+16u,28u);
            win_put64(bytes+40u,c->section);win_put32(bytes+48u,c->section_size);
            if(flags&1u)win_put64(bytes+56u,c->handle);
            win_put32(bytes+64u,file->roster);
        }else{
            win_put32(bytes+8u,(uint32_t)(c->section+file->data_offset));win_put32(bytes+12u,28u);
            win_put32(bytes+24u,(uint32_t)c->section);win_put32(bytes+28u,c->section_size);
            if(flags&1u)win_put32(bytes+32u,(uint32_t)c->handle);
            win_put32(bytes+36u,file->roster);
        }
        if(!win_write(p,arg[4],bytes,(size_t)cbsize))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(flags&1u)++c->references;
        *result=1u;return XXEMUL_STATUS_OK;
    }
}
