/* Explicit current-backed Windows page profile, independent of host permissions. */
#define WIN_MEMORY_PAGE_SIZE UINT64_C(4096)
static int win_memory_init(xxemul_windows *p,int dep)
{
    size_t i;uint64_t base=p->emulator->region_address,image_end=(p->image_size+4095u)&~UINT64_C(4095);
    p->memory_page_count=(p->emulator->region_size+4095u)/4096u;
    p->memory_pages=(win_memory_page*)calloc(p->memory_page_count,sizeof(*p->memory_pages));if(!p->memory_pages)return 0;
    p->memory_dep=(uint8_t)dep;
    for(i=0;i<p->memory_page_count;i++){win_memory_page *m=&p->memory_pages[i];m->allocation=i*4096u<image_end?base:base+image_end;m->protect=m->initial_protect=0x40u;m->state=0x1000u;m->type=i*4096u<image_end?0x1000000u:0x20000u;}
    return 1;
}
int xxemul_windows_memory_access(xxemul_windows *p,uint64_t address,uint64_t size,unsigned access,int fault)
{
    uint64_t base,span,last,first_bad=address;size_t first,end,i;
    if(!p||!p->memory_pages||!size)return 1;
    base=p->emulator->region_address;span=p->emulator->region_size;
    if(address<base||size>span||address-base>span-size){if(address>=base&&address-base<span)first_bad=base+span;goto denied;}
    last=address-base+size-1u;first=(size_t)((address-base)/4096u);end=(size_t)(last/4096u);
    for(i=first;i<=end;i++){
        win_memory_page *m=&p->memory_pages[i];uint32_t prot=m->protect;int allowed;
        if(access==1u)allowed=prot==4u||prot==0x40u;
        else if(access==8u)allowed=prot==0x20u||prot==0x40u||(!p->memory_dep&&(prot==2u||prot==4u));
        else allowed=prot==2u||prot==4u||prot==0x20u||prot==0x40u;
        if(m->state!=0x1000u||!allowed){first_bad=base+(uint64_t)i*4096u;if(first_bad<address)first_bad=address;goto denied;}
    }
    return 1;
 denied:
    if(fault){p->emulator->fault_address=first_bad;p->emulator->fault_address_valid=1;p->emulator->fault_access=(uint8_t)access;}
    return 0;
}
static int win_memory_protect_valid(uint32_t protect,uint32_t *error)
{
    if(protect==1u||protect==2u||protect==4u||protect==0x20u||protect==0x40u)return 1;
    *error=(protect==8u||protect==0x10u||protect==0x80u||(protect&0x700u))?50u:87u;return 0;
}
static int win_memory_api(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    uint64_t base=p->emulator->region_address;uint8_t width=win_word_size(p->emulator);*status=XXEMUL_STATUS_OK;
    if(win_equal(name,"VirtualAlloc")){
        uint64_t address,rounded;size_t first,last,i;uint32_t error=87u,protect=(uint32_t)arg[3],flags=(uint32_t)arg[2];win_allocation *entry;
        if(!win_memory_protect_valid(protect,&error)){p->last_error=error;return 1;}
        if(flags!=0x1000u&&flags!=0x2000u&&flags!=0x3000u){p->last_error=50u;return 1;}
        if(!arg[1]||arg[1]>UINT64_MAX-4095u){p->last_error=87u;return 1;}
        if(arg[0]){
            if(flags!=0x1000u){p->last_error=50u;return 1;}
            if(!win_memory_span(p,arg[0],arg[1])){p->last_error=487u;return 1;}
            first=(size_t)((arg[0]-base)/4096u);last=(size_t)((arg[0]-base+arg[1]-1u)/4096u)+1u;
            address=p->memory_pages[first].allocation;entry=win_find_allocation(p,address);
            if(!entry||entry->virtual_memory!=1u||arg[0]<address||arg[1]>entry->capacity||arg[0]-address>entry->capacity-arg[1]){p->last_error=487u;return 1;}
            for(i=first;i<last;i++)if(p->memory_pages[i].allocation!=address||(p->memory_pages[i].state!=0x1000u&&p->memory_pages[i].state!=0x2000u)){p->last_error=487u;return 1;}
            for(i=first;i<last;i++)if(p->memory_pages[i].state==0x2000u){
                memset(p->emulator->region_data+i*4096u,0,4096u);p->memory_pages[i].state=0x1000u;p->memory_pages[i].protect=protect;
            }
            *result=base+(uint64_t)first*4096u;return 1;
        }
        rounded=(arg[1]+4095u)&~UINT64_C(4095);address=(p->heap_cursor+65535u)&~UINT64_C(65535);
        if(address<p->heap_cursor||address>p->heap_limit||rounded>p->heap_limit-address||p->allocation_count>=WIN_MAX_ALLOCATIONS){p->last_error=8u;return 1;}
        first=(size_t)((address-base)/4096u);last=first+(size_t)(rounded/4096u);
        if(flags&0x1000u)memset(p->emulator->region_data+(size_t)(address-base),0,(size_t)rounded);
        entry=&p->allocations[p->allocation_count++];memset(entry,0,sizeof(*entry));entry->address=address;entry->size=arg[1];entry->capacity=rounded;entry->heap_owner=UINT64_MAX;entry->active=1u;entry->virtual_memory=1u;
        p->heap_cursor=address+rounded;
        for(i=first;i<last;i++){win_memory_page*m=&p->memory_pages[i];m->allocation=address;m->initial_protect=protect;m->state=(flags&0x1000u)?0x1000u:0x2000u;m->protect=(flags&0x1000u)?protect:0u;m->type=0x20000u;}
        *result=address;return 1;
    }
    if(win_equal(name,"VirtualFree")){
        win_allocation *entry;size_t first,last,i;uint32_t flags=(uint32_t)arg[2];uint64_t address,size;
        if(flags!=0x4000u&&flags!=0x8000u){p->last_error=50u;return 1;}
        if(flags==0x8000u){
            if(arg[1]||!(entry=win_find_allocation(p,arg[0]))||entry->virtual_memory!=1u){p->last_error=87u;return 1;}
            first=(size_t)((entry->address-base)/4096u);last=first+(size_t)(entry->capacity/4096u);
            for(i=first;i<last;i++){memset(&p->memory_pages[i],0,sizeof(p->memory_pages[i]));p->memory_pages[i].state=0x10000u;}
            /* Private tombstone prevents legacy heap reuse without a new virtual allocation transition. */
            entry->virtual_memory=2u;*result=1u;return 1;
        }
        if(!win_memory_span(p,arg[0],1u)){p->last_error=487u;return 1;}
        first=(size_t)((arg[0]-base)/4096u);address=p->memory_pages[first].allocation;entry=win_find_allocation(p,address);
        if(!entry||entry->virtual_memory!=1u){p->last_error=487u;return 1;}
        size=arg[1];if(!size){if(arg[0]!=address){p->last_error=87u;return 1;}size=entry->capacity;}
        if(arg[0]<address||size>entry->capacity||arg[0]-address>entry->capacity-size){p->last_error=487u;return 1;}
        last=(size_t)((arg[0]-base+size-1u)/4096u)+1u;
        for(i=first;i<last;i++)if(p->memory_pages[i].allocation!=address){p->last_error=487u;return 1;}
        for(i=first;i<last;i++){p->memory_pages[i].state=0x2000u;p->memory_pages[i].protect=0u;}
        *result=1u;return 1;
    }
    if(win_equal(name,"VirtualProtect")){
        size_t first,last,i;uint32_t error=87u,protect=(uint32_t)arg[2],old;
        if(!win_memory_protect_valid(protect,&error)){p->last_error=error;return 1;}
        if(!arg[1]||!win_memory_span(p,arg[0],arg[1])){p->last_error=487u;return 1;}
        first=(size_t)((arg[0]-base)/4096u);last=(size_t)((arg[0]-base+arg[1]-1u)/4096u);
        for(i=first;i<=last;i++)if(p->memory_pages[i].state!=0x1000u||p->memory_pages[i].allocation!=p->memory_pages[first].allocation){p->last_error=487u;return 1;}
        if(!arg[3]||!xxemul_windows_memory_access(p,arg[3],4u,1u,0)){p->last_error=998u;return 1;}
        old=p->memory_pages[first].protect;
        if(!win_store(p,arg[3],4u,old)){p->last_error=998u;return 1;}
        for(i=first;i<=last;i++)p->memory_pages[i].protect=protect;
        *result=1u;return 1;
    }
    if(win_equal(name,"VirtualQuery")){
        size_t index,end;uint32_t n=width==8u?48u:28u;uint8_t out[48]={0};win_memory_page *m;
        if(!win_memory_span(p,arg[0],1u)||arg[2]<n){p->last_error=87u;return 1;}
        if(!xxemul_windows_memory_access(p,arg[1],n,1u,0)){p->last_error=998u;return 1;}
        index=(size_t)((arg[0]-base)/4096u);m=&p->memory_pages[index];end=index+1u;
        while(end<p->memory_page_count&&!memcmp(m,&p->memory_pages[end],sizeof(*m)))++end;
        if(width==8u){win_put64(out,base+(uint64_t)index*4096u);win_put64(out+8,m->allocation);win_put32(out+16,m->initial_protect);win_put64(out+24,(uint64_t)(end-index)*4096u);win_put32(out+32,m->state);win_put32(out+36,m->protect);win_put32(out+40,m->type);}
        else{win_put32(out,(uint32_t)(base+(uint64_t)index*4096u));win_put32(out+4,(uint32_t)m->allocation);win_put32(out+8,m->initial_protect);win_put32(out+12,(uint32_t)((end-index)*4096u));win_put32(out+16,m->state);win_put32(out+20,m->protect);win_put32(out+24,m->type);}
        if(!win_write(p,arg[1],out,n)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}*result=n;return 1;
    }
    if(win_equal(name,"IsBadReadPtr")||win_equal(name,"IsBadWritePtr")){
        uint64_t max=width==8u?UINT64_MAX:UINT32_MAX;unsigned access=win_equal(name,"IsBadWritePtr")?1u:0u;
        *result=arg[1]&&(arg[0]>max||arg[1]-1u>max-arg[0]||!xxemul_windows_memory_access(p,arg[0],arg[1],access,0));return 1;
    }
    return 0;
}
