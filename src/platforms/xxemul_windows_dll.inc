/* Bounded guest PE DLL loader. All entry points execute as guest instructions. */
static win_module *win_dll_at(xxemul_windows *process, uint64_t handle)
{
    size_t i;
    for (i=0u;i<process->module_count;++i)
        if (process->modules[i].live && process->modules[i].base==handle) return &process->modules[i];
    return NULL;
}
static int win_guest_module_span(xxemul_windows *process,uint64_t handle,uint64_t *base,uint64_t *size,uint32_t *generation)
{
    win_module *module;
    if (!handle || handle==process->image_base) {
        *base=process->image_base;*size=process->image_size;*generation=1u;return 1;
    }
    module=win_dll_at(process,handle);
    if (!module || !module->real) return 0;
    *base=module->base;*size=module->image_size;*generation=module->generation;return 1;
}
static int win_dll_rva(xxemul_windows *process,const win_module *module,uint64_t rva,uint64_t count,const uint8_t **bytes)
{
    if (!module->live || rva>module->image_size || count>module->image_size-rva) return 0;
    if (bytes) *bytes=process->emulator->region_data+(size_t)(module->base-process->image_base+rva);
    return 1;
}
static int win_dll_string(xxemul_windows *process,const win_module *module,uint32_t rva,char *text,size_t capacity)
{
    const uint8_t *bytes;size_t i;
    if (!win_dll_rva(process,module,rva,1u,&bytes)) return 0;
    for(i=0u;i<capacity && i<module->image_size-rva;++i){text[i]=(char)bytes[i];if(!bytes[i])return 1;}
    return 0;
}
static int win_dll_host_path(xxemul_windows *process,const char *name,char *host,size_t capacity)
{
    char guest[2048];size_t length;
#if !defined(_WIN32)
    struct stat info;
#endif
    if (!win_copy(guest,sizeof(guest),name)) return 0;
    length=strlen(guest);
    {const char *base=guest,*p;for(p=guest;*p;++p)if(*p=='/'||*p=='\\')base=p+1;
     if (!strchr(base,'.')) {if(length+5u>sizeof(guest))return 0;memcpy(guest+length,".dll",5u);}}
    if (!win_guest_path(process,guest,host,capacity)) return 0;
#if defined(_WIN32)
    {DWORD attributes=GetFileAttributesA(host);
     return attributes!=INVALID_FILE_ATTRIBUTES && !(attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));}
#else
    if (stat(host,&info)==0) return S_ISREG(info.st_mode)!=0;
    /* Case-insensitive final-component lookup, confined by win_guest_path. */
    {char directory[2048],actual[2048],*slash;DIR *dir;struct dirent *item;int found=0;
     if (!win_copy(directory,sizeof(directory),host)) return 0;
     slash=strrchr(directory,'/');if(!slash)return 0;*slash=0;
     dir=opendir(directory);if(!dir)return 0;
     while((item=readdir(dir))!=NULL){
         if(!win_equal(item->d_name,slash+1))continue;
         if(snprintf(actual,sizeof(actual),"%s/%s",directory,item->d_name)>=(int)sizeof(actual))break;
         if(!win_guest_path(process,actual,host,capacity))break;
         if(lstat(host,&info)==0 && S_ISREG(info.st_mode))found=1;
         break;
     }
     closedir(dir);return found;}
#endif
}
static uint32_t win_dll_dependencies_release(xxemul_windows *process,size_t slot)
{
    win_module *module=&process->modules[slot];uint32_t mask=0u;size_t i;
    if(!module->live || !module->real || !module->references || module->references==UINT32_MAX)return 0u;
    if(--module->references)return 0u;
    mask=UINT32_C(1)<<slot;
    for(i=0u;i<process->module_count;++i)
        if(module->dependencies&(UINT32_C(1)<<i))mask|=win_dll_dependencies_release(process,i);
    return mask;
}
static void win_dll_discard(xxemul_windows *process,size_t slot)
{
    win_module *module=&process->modules[slot];win_allocation *allocation;
    if(!module->real || !module->live)return;
    win_tls_release_image(process,&module->tls);
    if(!module->primary)memset(process->emulator->region_data+(size_t)(module->base-process->image_base),0,(size_t)module->image_size);
    allocation=win_find_allocation(process,module->allocation);
    if(allocation)allocation->active=0u;
    module->live=0u;module->initialized=0u;module->initializing=0u;module->references=0u;
    (void)win_loader_lists(process);
}
static void win_dll_rollback(xxemul_windows *process,size_t slot)
{
    uint32_t mask=win_dll_dependencies_release(process,slot);size_t i;
    for(i=0u;i<process->module_count;++i)if(mask&(UINT32_C(1)<<i))win_dll_discard(process,i);
}
static uint64_t win_dll_export(xxemul_windows *process,win_module *module,const char *name,unsigned depth,int by_ordinal);
static uint64_t win_dll_load(xxemul_windows *process,const char *name,uint32_t flags)
{
    char host[2048];FILE *file;long length;uint8_t *raw=NULL;xxemul *mapped=NULL;
    uint32_t nt,optional,image_size,entry,dir_offset,headers,section_count;uint16_t optional_size;
    uint64_t allocation=0u,base;size_t i,slot;win_module *module;xxemul_status status;uint32_t generation;
    process->last_error=0u;
    if(process->emulator->arch!=XXEMUL_ARCH_X86){process->last_error=120u;return 0u;}
    if(process->dll_exiting){process->last_error=1115u;return 0u;}
    if(flags&~UINT32_C(1)){process->last_error=120u;return 0u;}
    if(!win_dll_host_path(process,name,host,sizeof(host))){process->last_error=126u;return 0u;}
    for(i=0u;i<process->module_count;++i){module=&process->modules[i];
        if(module->real&&module->live&&win_equal(module->file_path,host)){
            if(module->references!=UINT32_MAX){if(module->references==UINT32_MAX-1u){process->last_error=8u;return 0u;}++module->references;}
            return module->base;}}
    slot=process->module_count;
    for(i=0u;i<process->module_count;++i)if(process->modules[i].real&&!process->modules[i].live){slot=i;break;}
    if(slot==WIN_MAX_MODULES){process->last_error=8u;return 0u;}
    file=fopen(host,"rb");if(!file){process->last_error=5u;return 0u;}
    if(fseek(file,0,SEEK_END)!=0||(length=ftell(file))<0 || length>WIN_MAX_IO || fseek(file,0,SEEK_SET)!=0){fclose(file);process->last_error=193u;return 0u;}
    if(length<64 || !(raw=(uint8_t*)malloc((size_t)length))){fclose(file);process->last_error=length<64?193u:8u;return 0u;}
    if(fread(raw,1,(size_t)length,file)!=(size_t)length){fclose(file);free(raw);process->last_error=193u;return 0u;}fclose(file);
    nt=win_le32(raw+0x3c);optional=nt+24u;dir_offset=win_word_size(process->emulator)==8u?112u:96u;
    if(raw[0]!='M'||raw[1]!='Z'||nt>(uint32_t)length-24u||memcmp(raw+nt,"PE\0\0",4u) ||
       win_le16(raw+nt+4u)!=(win_word_size(process->emulator)==8u?0x8664u:0x14cu)||!(win_le16(raw+nt+22u)&0x2000u))goto invalid;
    optional_size=win_le16(raw+nt+20u);
    if(optional_size<dir_offset+16u*8u || optional_size>(uint32_t)length || optional>(uint32_t)length-optional_size ||
       win_le16(raw+optional)!=(win_word_size(process->emulator)==8u?0x20bu:0x10bu))goto invalid;
    image_size=win_le32(raw+optional+56u);entry=win_le32(raw+optional+16u);headers=win_le32(raw+optional+60u);section_count=win_le16(raw+nt+6u);
    if(!image_size || image_size>WIN_MAX_IO || entry>=image_size || headers>image_size || headers>(uint32_t)length ||
       !section_count || section_count>96u || section_count*40u>(uint32_t)length || optional+optional_size>(uint32_t)length-section_count*40u)goto invalid;
    /* Delay imports and CLR are not silently accepted. */
    if(win_le32(raw+optional+dir_offset+13u*8u)||win_le32(raw+optional+dir_offset+14u*8u)){
        process->last_error=120u;goto failed;}
    if(process->dll_generation==UINT32_MAX){process->last_error=8u;goto failed;}
    allocation=win_heap_alloc(process,(uint64_t)image_size+0xffffu);if(!allocation){process->last_error=8u;goto failed;}
    base=(allocation+0xffffu)&~UINT64_C(0xffff);
    mapped=xxemul_create_image_at(win_word_size(process->emulator)==8u?XXEMUL_IMAGE_PE64:XXEMUL_IMAGE_PE32,raw,(size_t)length,base,&status);
    if(!mapped){process->last_error=status==XXEMUL_STATUS_OUT_OF_MEMORY?8u:193u;goto failed;}
    module=&process->modules[slot];generation=++process->dll_generation;
    memset(module,0,sizeof(*module));module->generation=generation;module->base=base;module->allocation=allocation;
    module->image_size=image_size;module->entry_rva=entry;module->references=1u;module->real=1u;module->live=1u;
    module->data_only=(uint8_t)(flags&1u);module->initialized=module->data_only;
    if(slot==process->module_count)++process->module_count;
    module->export_rva=win_le32(raw+optional+dir_offset);module->export_size=win_le32(raw+optional+dir_offset+4u);
    module->resource_rva=win_le32(raw+optional+dir_offset+16u);module->resource_size=win_le32(raw+optional+dir_offset+20u);
    if(!win_copy(module->file_path,sizeof(module->file_path),host))goto module_failed;
    {const char *leaf=host,*p;for(p=host;*p;++p)if(*p=='/'||*p=='\\')leaf=p+1;
     if(!win_copy(module->name,sizeof(module->name),leaf))goto module_failed;
     for(i=0u;module->name[i];++i)module->name[i]=(char)tolower((unsigned char)module->name[i]);}
    if(!win_write(process,base,mapped->region_data,image_size))goto module_failed;
    xxemul_destroy(mapped);mapped=NULL;
    if(!module->data_only){
        if(!win_tls_bind_image(process,&module->tls,base,image_size,
             win_le32(raw+optional+dir_offset+9u*8u),win_le32(raw+optional+dir_offset+9u*8u+4u),(uint32_t)slot+1u,0)){
            if(!process->last_error)process->last_error=193u;
            goto module_failed;
        }
        uint32_t imports=win_le32(raw+optional+dir_offset+8u),size=win_le32(raw+optional+dir_offset+12u);const uint8_t *descriptor;
        if(imports){uint64_t cursor=0u;int terminated=0;
            if(size<20u || !win_dll_rva(process,module,imports,size,&descriptor))goto module_failed;
            while(cursor+20u<=size){uint32_t lookup=win_le32(descriptor+cursor),dll=win_le32(descriptor+cursor+12u),iat=win_le32(descriptor+cursor+16u);char dependency[48];size_t symbol;win_module *dep;
                if(!lookup&&!dll&&!iat){terminated=1;break;}
                if(!dll||!iat||!win_dll_string(process,module,dll,dependency,sizeof(dependency)))goto module_failed;
                dep=win_find_module(process,dependency,0);
                if(!dep){if(win_loadable_module(process,dependency))dep=win_find_module(process,dependency,1);
                    else{uint64_t handle=win_dll_load(process,dependency,0u);dep=win_dll_at(process,handle);}}
                else if(dep->real && !dep->init_order && !dep->data_only){process->last_error=120u;goto module_failed;}
                else if(dep->real && !(module->dependencies&(UINT32_C(1)<<(size_t)(dep-process->modules)))){
                    if(dep->references==UINT32_MAX-1u)goto module_failed;
                    if(dep->references!=UINT32_MAX)++dep->references;}
                if(!dep)goto module_failed;
                if(dep->real){size_t dependency_slot=(size_t)(dep-process->modules);if(dep==module)goto module_failed;module->dependencies|=UINT32_C(1)<<dependency_slot;}
                if(!lookup)lookup=iat;
                for(symbol=0u;symbol<4096u;++symbol){const uint8_t *value;uint64_t raw_symbol,address;char function[96];
                    uint8_t width=win_word_size(process->emulator);uint64_t source=(uint64_t)lookup+symbol*width,destination=(uint64_t)iat+symbol*width;
                    if(!win_dll_rva(process,module,source,width,&value)||!win_dll_rva(process,module,destination,width,NULL))goto module_failed;
                    raw_symbol=width==8u?win_le64(value):win_le32(value);if(!raw_symbol)break;
                    if(raw_symbol&(width==8u?UINT64_C(0x8000000000000000):UINT64_C(0x80000000)))snprintf(function,sizeof(function),"#%u",(unsigned)(raw_symbol&0xffffu));
                    else if(raw_symbol>UINT32_MAX-2u || !win_dll_string(process,module,(uint32_t)raw_symbol+2u,function,sizeof(function)))goto module_failed;
                    address=dep->real?win_dll_export(process,dep,function,0u,(raw_symbol&(width==8u?UINT64_C(0x8000000000000000):UINT64_C(0x80000000)))!=0u):win_resolve(process,dep->name,function);
                    if(!address||!win_store(process,base+destination,width,address))goto module_failed;
                }
                if(symbol==4096u)goto module_failed;
                cursor+=20u;
            }
            if(!terminated)goto module_failed;
        }
        module->init_order=++process->dll_sequence;
    }
    if(!win_loader_lists(process))goto module_failed;
    free(raw);return base;
invalid:process->last_error=193u;
failed:
    if(mapped)xxemul_destroy(mapped);
    if(allocation){win_allocation *block=win_find_allocation(process,allocation);if(block)block->active=0u;}
    free(raw);return 0u;
module_failed:
    if(!process->last_error)process->last_error=193u;
    if(mapped)xxemul_destroy(mapped);
    win_dll_rollback(process,slot);free(raw);return 0u;
}
static int win_dll_reaches(const xxemul_windows *process,size_t from,size_t target,uint32_t visited)
{
    size_t i;
    if(from==target)return 1;
    if(visited&(UINT32_C(1)<<from))return 0;
    visited|=UINT32_C(1)<<from;
    for(i=0u;i<process->module_count;++i)
        if((process->modules[from].dependencies&(UINT32_C(1)<<i))&&win_dll_reaches(process,i,target,visited))return 1;
    return 0;
}
static uint64_t win_dll_export(xxemul_windows *process,win_module *module,const char *name,unsigned depth,int by_ordinal)
{
    const uint8_t *directory,*item;uint32_t ordinal_base,count,names,index=UINT32_MAX,function_rva;size_t i;
    if(depth>=8u || !module->live || !module->export_rva || module->export_size<40u ||
       !win_dll_rva(process,module,module->export_rva,module->export_size,&directory))return 0u;
    ordinal_base=win_le32(directory+16u);count=win_le32(directory+20u);names=win_le32(directory+24u);
    if(count>65536u || names>4096u || !win_dll_rva(process,module,win_le32(directory+28u),(uint64_t)count*4u,NULL) ||
       !win_dll_rva(process,module,win_le32(directory+32u),(uint64_t)names*4u,NULL) ||
       !win_dll_rva(process,module,win_le32(directory+36u),(uint64_t)names*2u,NULL))return 0u;
    if(by_ordinal){if(name[0]!='#')return 0u;char *end;unsigned long ordinal=strtoul(name+1,&end,10);
        if(!name[1]||*end||ordinal<ordinal_base||ordinal-ordinal_base>=count)return 0u;
        index=(uint32_t)(ordinal-ordinal_base);}
    else for(i=0u;i<names;++i){uint32_t rva;char exported[96];
        if(!win_dll_rva(process,module,(uint64_t)win_le32(directory+32u)+i*4u,4u,&item))return 0u;
        rva=win_le32(item);
        if(!win_dll_string(process,module,rva,exported,sizeof(exported)))return 0u;
        if(strcmp(exported,name))continue;
        if(!win_dll_rva(process,module,(uint64_t)win_le32(directory+36u)+i*2u,2u,&item))return 0u;
        index=win_le16(item);break;}
    if(index>=count || !win_dll_rva(process,module,(uint64_t)win_le32(directory+28u)+index*4u,4u,&item))return 0u;
    function_rva=win_le32(item);if(!function_rva||!win_dll_rva(process,module,function_rva,1u,NULL))return 0u;
    if(function_rva>=module->export_rva && function_rva-module->export_rva<module->export_size){
        char forward[145],*dot;win_module *destination;const char *function;int existed;
        if(!win_dll_string(process,module,function_rva,forward,sizeof(forward)) || !(dot=strrchr(forward,'.')))return 0u;
        *dot=0;function=dot+1;if(!*forward||!*function)return 0u;
        destination=win_find_module(process,forward,0);existed=destination!=NULL;
        if(!destination){if(win_loadable_module(process,forward))destination=win_find_module(process,forward,1);
            else destination=win_dll_at(process,win_dll_load(process,forward,0u));}
        if(!destination)return 0u;
        if(destination->real){size_t slot=(size_t)(destination-process->modules);
            if(destination==module)return win_dll_export(process,destination,function,depth+1u,function[0]=='#');
            if(win_dll_reaches(process,slot,(size_t)(module-process->modules),0u)){
                if(!existed)win_dll_rollback(process,slot);
                process->last_error=120u;return 0u;
            }
            if(!(module->dependencies&(UINT32_C(1)<<slot))){module->dependencies|=UINT32_C(1)<<slot;
                /* Newly loaded forwarder modules already own the reference. */
                if(existed && destination->references!=UINT32_MAX)++destination->references;}
            return win_dll_export(process,destination,function,depth+1u,function[0]=='#');}
        return win_resolve(process,destination->name,function);
    }
    return module->base+function_rva;
}
static int win_dll_thread_active(xxemul_windows *process)
{
    size_t i;uint32_t owner=process->threads[process->thread_current].id;
    for(i=0u;i<process->dll_depth;++i)if(process->dll_frames[i].owner_id==owner)return 1;
    return 0;
}
#include "xxemul_windows_notify.inc"
