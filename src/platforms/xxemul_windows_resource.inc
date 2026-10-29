/* PE resources are already mapped guest bytes. No host resource loading occurs. */
#define WIN_RESOURCE_TOKEN_BASE UINT64_C(0x70000000)
#define WIN_RESOURCE_TOKEN_STRIDE UINT64_C(0x10)
#define WIN_RESOURCE_NAME_UNITS 255u
#define WIN_RESOURCE_DIRECTORY_ENTRIES 4096u

typedef struct win_resource_key {
    uint16_t id, text[WIN_RESOURCE_NAME_UNITS];
    size_t length;
    uint8_t named;
} win_resource_key;
typedef struct win_resource_image {
    uint64_t base, size, root;
    uint32_t directory_size, generation;
} win_resource_image;

static int win_resource_span(const win_resource_image *image,uint64_t rva,uint64_t count)
{
    return count<=image->size && rva<=image->size-count && image->base<=UINT64_MAX-rva;
}
static int win_resource_read(xxemul_windows *process,const win_resource_image *image,uint64_t offset,unsigned width,uint64_t *value)
{
    return offset<=image->directory_size && width<=image->directory_size-offset &&
        win_load(process,image->root+offset,(uint8_t)width,value);
}
static uint16_t win_resource_upper(uint16_t ch)
{
    if(ch>='a'&&ch<='z')return (uint16_t)(ch-('a'-'A'));
    if((ch>=0xe0u&&ch<=0xf6u)||(ch>=0xf8u&&ch<=0xfeu))return (uint16_t)(ch-0x20u);
    if(ch==0xffu)return 0x178u;
    if(ch==0x153u)return 0x152u;
    if(ch==0x161u)return 0x160u;
    if(ch==0x17eu)return 0x17du;
    return ch;
}
static int win_resource_key_read(xxemul_windows *process,uint64_t pointer,int wide,win_resource_key *key)
{
    size_t used=0u;
    memset(key,0,sizeof(*key));
    if(pointer<UINT64_C(0x10000)){key->id=(uint16_t)pointer;return 1;}
    key->named=1u;
    while(used<WIN_RESOURCE_NAME_UNITS){
        uint64_t value;
        if(pointer>UINT64_MAX-used*(wide?2u:1u)||!win_load(process,pointer+used*(wide?2u:1u),wide?2u:1u,&value))return 0;
        if(!value)break;
        if(!wide&&value>=0x80u&&value<0xa0u)value=win_cp1252_upper[value-0x80u];
        key->text[used++]=(uint16_t)value;
    }
    if(used==WIN_RESOURCE_NAME_UNITS)return 0;
    key->length=used;
    if(used>1u&&key->text[0]=='#'){
        uint32_t number=0u;size_t index;
        for(index=1u;index<used;++index){
            if(key->text[index]<'0'||key->text[index]>'9')return 1;
            number=number*10u+(key->text[index]-'0');
            if(number>UINT16_MAX)return 0;
        }
        key->named=0u;key->id=(uint16_t)number;key->length=0u;
    }
    return 1;
}
static int win_resource_image_open(xxemul_windows *process,uint64_t module,win_resource_image *image)
{
    uint64_t pe,optional,magic,optional_size,resource_rva,resource_size,directories;
    uint32_t generation;
    memset(image,0,sizeof(*image));
    if(!win_guest_module_span(process,module,&image->base,&image->size,&generation)){
        process->last_error=6u;return 0;
    }
    image->generation=generation;
    if(!win_resource_span(image,0u,0x40u)||!win_load(process,image->base,2u,&magic)||magic!=0x5a4du||
       !win_load(process,image->base+0x3cu,4u,&pe)||!win_resource_span(image,pe,24u)||
       !win_load(process,image->base+pe,4u,&magic)||magic!=0x4550u||
       !win_load(process,image->base+pe+20u,2u,&optional_size))goto malformed;
    optional=pe+24u;
    if(!win_resource_span(image,optional,optional_size)||optional_size<2u||
       !win_load(process,image->base+optional,2u,&magic))goto malformed;
    directories=magic==0x10bu?96u:magic==0x20bu?112u:0u;
    if(!directories||optional_size<directories||
       !win_load(process,image->base+optional+directories-4u,4u,&magic))goto malformed;
    if(magic<3u||optional_size<directories+24u){process->last_error=1812u;return 0;}
    if(!win_load(process,image->base+optional+directories+16u,4u,&resource_rva)||
       !win_load(process,image->base+optional+directories+20u,4u,&resource_size))goto malformed;
    if(!resource_rva&&!resource_size){process->last_error=1812u;return 0;}
    if(!resource_rva||resource_size<16u||!win_resource_span(image,resource_rva,resource_size))goto malformed;
    image->root=image->base+resource_rva;image->directory_size=(uint32_t)resource_size;return 1;
malformed:
    process->last_error=193u;return 0;
}
static int win_resource_key_match(xxemul_windows *process,const win_resource_image *image,uint32_t value,const win_resource_key *key,int *matched)
{
    uint64_t length,word;size_t index;uint64_t offset=value&UINT32_C(0x7fffffff);
    *matched=0;
    if(!(value&UINT32_C(0x80000000))){
        if(value>UINT16_MAX)return 0;
        *matched=!key->named&&key->id==value;return 1;
    }
    if(!win_resource_read(process,image,offset,2u,&length)||length>WIN_RESOURCE_NAME_UNITS||
       offset+2u>image->directory_size||length*2u>image->directory_size-(offset+2u))return 0;
    if(!key->named||key->length!=length)return 1;
    *matched=1;
    for(index=0u;index<length;++index){
        if(!win_resource_read(process,image,offset+2u+index*2u,2u,&word))return 0;
        if(win_resource_upper((uint16_t)word)!=win_resource_upper(key->text[index]))*matched=0;
    }
    return 1;
}
static int win_resource_child(xxemul_windows *process,const win_resource_image *image,uint32_t directory,
                              const win_resource_key *key,int language_mode,uint16_t language,uint32_t *child,unsigned absent)
{
    uint64_t named,ids,raw_key,value;size_t index,count;int found=0,best=100;
    if(!win_resource_read(process,image,(uint64_t)directory+12u,2u,&named)||
       !win_resource_read(process,image,(uint64_t)directory+14u,2u,&ids)||
       named+ids>WIN_RESOURCE_DIRECTORY_ENTRIES || (uint64_t)directory+16u>image->directory_size ||
       (named+ids)*8u>image->directory_size-((uint64_t)directory+16u))goto malformed;
    count=(size_t)(named+ids);
    for(index=0u;index<count;++index){
        int match=0,rank=0;
        if(!win_resource_read(process,image,(uint64_t)directory+16u+index*8u,4u,&raw_key)||
           !win_resource_read(process,image,(uint64_t)directory+20u+index*8u,4u,&value))goto malformed;
        if((index<named)!=(!!(raw_key&UINT32_C(0x80000000))))goto malformed;
        if(!language_mode){if(!win_resource_key_match(process,image,(uint32_t)raw_key,key,&match))goto malformed;}
        else{
            if(raw_key>UINT16_MAX || value&UINT32_C(0x80000000))goto malformed;
            if(language_mode==1){match=raw_key==language;rank=0;}
            else{
                match=1;
                /* The process model supplies neutral/en-US resources; there
                 * are no host-dependent MUI files or preferred-language lists. */
                rank=raw_key==0u?0:raw_key==0x409u?1:raw_key==9u?2:3;
            }
        }
        if(!match)continue;
        if(found&&rank==best&&(!language_mode||language_mode==1))goto malformed;
        if(!found||rank<best){*child=(uint32_t)value;best=rank;found=1;}
    }
    if(found)return 1;
    process->last_error=absent;return 0;
malformed:
    process->last_error=193u;return 0;
}
static int win_resource_lookup(xxemul_windows *process,uint64_t module,const win_resource_key *type,const win_resource_key *name,
                               int explicit_language,uint16_t language,win_resource_image *image,uint32_t *entry,uint64_t *address,uint32_t *size)
{
    uint32_t type_dir,name_dir,data_entry;uint64_t payload,amount,reserved;
    if(!win_resource_image_open(process,module,image))return 0;
    if(!win_resource_child(process,image,0u,type,0,0u,&type_dir,1813u))return 0;
    if(!(type_dir&UINT32_C(0x80000000)))goto malformed;
    type_dir&=UINT32_C(0x7fffffff);
    if(!win_resource_child(process,image,type_dir,name,0,0u,&name_dir,1814u))return 0;
    if(!(name_dir&UINT32_C(0x80000000)))goto malformed;
    name_dir&=UINT32_C(0x7fffffff);
    if(!win_resource_child(process,image,name_dir,NULL,explicit_language?1:2,language?language:0x409u,&data_entry,1815u))return 0;
    if(data_entry&UINT32_C(0x80000000)||
       !win_resource_read(process,image,data_entry,4u,&payload)||
       !win_resource_read(process,image,(uint64_t)data_entry+4u,4u,&amount)||
       !win_resource_read(process,image,(uint64_t)data_entry+12u,4u,&reserved)||reserved||
       !win_resource_span(image,payload,amount))goto malformed;
    *entry=data_entry;*address=image->base+payload;*size=(uint32_t)amount;return 1;
malformed:
    process->last_error=193u;return 0;
}
static win_resource_record *win_resource_at(xxemul_windows *process,uint64_t token,int loaded)
{
    uint64_t difference,index,base,size;uint32_t generation;
    if(token<WIN_RESOURCE_TOKEN_BASE)return NULL;
    difference=token-WIN_RESOURCE_TOKEN_BASE;
    if(difference%WIN_RESOURCE_TOKEN_STRIDE!=(loaded?1u:0u))return NULL;
    index=difference/WIN_RESOURCE_TOKEN_STRIDE;
    if(index>=WIN_RESOURCE_RECORDS||!process->resource_records[index].used)return NULL;
    if(loaded&&!process->resource_records[index].loaded)return NULL;
    if(!win_guest_module_span(process,process->resource_records[index].module,&base,&size,&generation)||
       generation!=process->resource_records[index].generation||base!=process->resource_records[index].module)return NULL;
    return &process->resource_records[index];
}
static int win_resource_call(xxemul_windows *process,const char *api,const uint64_t *arg,uint64_t *result)
{
    if(!strcmp(api,"FindResourceA")||!strcmp(api,"FindResourceW")||!strcmp(api,"FindResourceExA")||!strcmp(api,"FindResourceExW")){
        win_resource_key type,name;win_resource_image image;uint32_t entry,size;uint64_t address;size_t index;
        int extended=strstr(api,"Ex")!=NULL,wide=api[strlen(api)-1u]=='W';
        if(!win_resource_key_read(process,arg[extended?1u:2u],wide,&type)||
           !win_resource_key_read(process,arg[extended?2u:1u],wide,&name)){
            process->last_error=998u;return 1;
        }
        if(!win_resource_lookup(process,arg[0],&type,&name,extended,(uint16_t)arg[3],&image,&entry,&address,&size))return 1;
        for(index=0u;index<WIN_RESOURCE_RECORDS;++index){
            win_resource_record *record=&process->resource_records[index];
            if(record->used&&record->module==image.base&&record->generation==image.generation&&record->entry==entry){
                *result=WIN_RESOURCE_TOKEN_BASE+index*WIN_RESOURCE_TOKEN_STRIDE;return 1;
            }
        }
        for(index=0u;index<WIN_RESOURCE_RECORDS;++index){
            win_resource_record *record=&process->resource_records[index];
            if(record->used)continue;
            memset(record,0,sizeof(*record));record->module=image.base;record->generation=image.generation;
            record->entry=entry;record->address=address;record->size=size;record->used=1u;
            *result=WIN_RESOURCE_TOKEN_BASE+index*WIN_RESOURCE_TOKEN_STRIDE;return 1;
        }
        process->last_error=8u;return 1;
    }
    if(!strcmp(api,"LoadResource")||!strcmp(api,"SizeofResource")){
        win_resource_record *record=win_resource_at(process,arg[1],0);uint64_t base,image_size;uint32_t generation;
        if(!record||!win_guest_module_span(process,arg[0],&base,&image_size,&generation)||base!=record->module||generation!=record->generation){
            process->last_error=6u;return 1;
        }
        if(!strcmp(api,"SizeofResource"))*result=record->size;
        else{record->loaded=1u;*result=arg[1]+1u;}
        return 1;
    }
    if(!strcmp(api,"LockResource")){
        win_resource_record *record=win_resource_at(process,arg[0],1);
        if(record)*result=record->address;else process->last_error=6u;
        return 1;
    }
    if(!strcmp(api,"FreeResource")){
        /* Obsolete Win32 API always returns FALSE; mapped data stays valid. */
        *result=0u;return 1;
    }
    return 0;
}
