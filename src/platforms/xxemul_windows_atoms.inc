/* Session-local global atom table. It is intentionally independent of class
 * atoms and registered-message identifiers, even when numeric values overlap. */
static xxemul_windows *win_atom_owner(xxemul_windows *p)
{
    return p->process_tree?p->process_tree->root:p;
}
static uint32_t win_atom_hash(const uint16_t *s)
{
    uint32_t h=2166136261u;
    while(*s){
        uint16_t c=win_reg_fold(*s++);
        h=(h^(uint8_t)c)*16777619u;
        h=(h^(uint8_t)(c>>8))*16777619u;
    }
    return h;
}
static uint16_t win_atom_find_name(xxemul_windows *p,const uint16_t *s)
{
    win_global_atoms *r=win_atom_owner(p)->global_atoms;
    uint32_t h=win_atom_hash(s);
    uint16_t n;
    if(!r)return 0;
    for(n=r->buckets[h&1023u];n;n=r->entries[n-1u].next){
        win_global_atom *e=&r->entries[n-1u];
        if(e->hash==h&&win_reg_name_equal(e->name,s))return (uint16_t)(0xbfffu+n);
    }
    return 0;
}
static int win_atom_live(xxemul_windows *p,uint16_t atom)
{
    win_global_atoms *r=win_atom_owner(p)->global_atoms;
    return atom&&((atom<0xc000u)||(r&&(uint32_t)(atom-0xc000u)<r->count&&r->entries[atom-0xc000u].name));
}
static uint16_t win_atom_add_name(xxemul_windows *p,const uint16_t *s)
{
    xxemul_windows *owner=win_atom_owner(p);
    win_global_atoms *r=owner->global_atoms;
    win_global_atom *e;
    uint16_t atom=win_atom_find_name(p,s),link;
    uint32_t h=win_atom_hash(s);
    size_t n=0;
    if(atom){
        e=&r->entries[atom-0xc000u];
        if(e->references==UINT32_MAX){
            p->last_error=8u;
            return 0;
        }
        ++e->references;
        return atom;
    }
    if(!r){
        r=(win_global_atoms*)calloc(1,sizeof(*r));
        if(!r){
            p->last_error=8u;
            return 0;
        }
        owner->global_atoms=r;
    }
    if(!r->free_head&&r->count==0x4000u){
        p->last_error=8u;
        return 0;
    }
    while(s[n])++n;
    e=NULL;
    {
        uint16_t *copy=(uint16_t*)malloc((n+1u)*sizeof(*copy));
        if(!copy){
            p->last_error=8u;
            return 0;
        }
        memcpy(copy,s,(n+1u)*sizeof(*copy));
        if(r->free_head){
            link=r->free_head;
            e=&r->entries[link-1u];
            r->free_head=e->next;
        }
        else{
            link=(uint16_t)(++r->count);
            e=&r->entries[link-1u];
        }
        memset(e,0,sizeof(*e));
        e->name=copy;
    }
    e->references=1;
    e->hash=h;
    e->next=r->buckets[h&1023u];
    r->buckets[h&1023u]=link;
    return (uint16_t)(0xbfffu+link);
}
static int win_atom_delete(xxemul_windows *p,uint16_t atom)
{
    win_global_atoms *r=win_atom_owner(p)->global_atoms;
    win_global_atom *e;
    uint16_t *link;
    if(atom&&atom<0xc000u)return 1;
    if(!win_atom_live(p,atom))return 0;
    e=&r->entries[atom-0xc000u];
    if(--e->references)return 1;
    link=&r->buckets[e->hash&1023u];
    while(*link&&*link!=(uint16_t)(atom-0xbfffu))link=&r->entries[*link-1u].next;
    if(*link)*link=e->next;
    free(e->name);
    memset(e,0,sizeof(*e));
    e->next=r->free_head;
    r->free_head=(uint16_t)(atom-0xbfffu);
    return 1;
}
/* Decode MAKEINTATOM and decimal #n without ever treating a small selector as
 * a guest string pointer. The bounded text profile accepts 255 UTF-16 units. */
static uint32_t win_atom_selector(xxemul_windows *p,uint64_t address,int wide,uint16_t *name,uint16_t *integer)
{
    uint32_t error;
    size_t i;
    uint32_t n=0;
    *integer=0;
    name[0]=0;
    if(address<=0xffffu){
        if(address&&address<0xc000u){
            *integer=(uint16_t)address;
            return 0;
        }
        return 87u;
    }
    error=win_reg_name(p,address,wide,name,256u,0);
    if(error)return error;
    if(!name[0])return 87u;
    if(name[0]=='#'&&name[1]){
        /* A nondecimal suffix makes the whole selector an ordinary string,
                         * even when its numeric prefix would overflow an integer atom. */
        for(i=1;name[i];i++)if(name[i]<'0'||name[i]>'9')return 0;
        for(i=1;name[i];i++){
            if(n>49151u/10u)return 87u;
            n=n*10u+name[i]-'0';
            if(n>=0xc000u)return 87u;
        }
        if(!n)return 87u;
        *integer=(uint16_t)n;
    }
    return 0;
}
static int win_global_atom_call(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    uint16_t s[256],integer,atom;
    uint32_t error;
    int add=win_equal(name,"GlobalAddAtomA")||win_equal(name,"GlobalAddAtomW"),find=win_equal(name,"GlobalFindAtomA")||win_equal(name,"GlobalFindAtomW");
    *status=XXEMUL_STATUS_OK;
    if(win_equal(name,"GlobalGetAtomNameA")||win_equal(name,"GlobalGetAtomNameW")){
        const uint16_t *text;
        uint16_t integral[8];uint8_t output[512];
        win_global_atoms *table=win_atom_owner(p)->global_atoms;
        size_t length=0,copied,i;int32_t capacity=(int32_t)arg[2];
        int wide=win_suffix(name,"W");atom=(uint16_t)arg[0];
        if(capacity<=0){p->last_error=234u;return 1;}
        if(!atom||!win_atom_live(p,atom)){p->last_error=6u;return 1;}
        if(atom<0xc000u){
            char decimal[8];int n=snprintf(decimal,sizeof(decimal),"#%u",(unsigned)atom);
            if(n<=0||(size_t)n>=sizeof(decimal)){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
            for(i=0;i<=(size_t)n;i++)integral[i]=(uint8_t)decimal[i];
            text=integral;
        }else text=table->entries[atom-0xc000u].name;
        while(text[length])++length;
        copied=length<(size_t)capacity?length:(size_t)capacity-(wide?0u:1u);
        for(i=0;i<copied;i++){
            if(wide)win_put16(output+i*2u,text[i]);
            else output[i]=win_reg_unansi(text[i]);
        }
        if(wide){
            /* The native wide API may fill the buffer without a terminator;
             * the ANSI wrapper instead reserves its terminating byte. */
            int terminated=copied<(size_t)capacity;
            if(terminated)win_put16(output+copied*2u,0u);
            if(!win_write(p,arg[1],output,(copied+(terminated?1u:0u))*2u)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
            if(copied!=length)p->last_error=234u;
            *result=copied;
        }else{
            output[copied]=0u;
            if(!win_write(p,arg[1],output,copied+1u)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
            if(copied!=length)p->last_error=234u;else *result=length;
        }
        return 1;
    }
    if(win_equal(name,"GlobalDeleteAtom")){
        if(!win_atom_delete(p,(uint16_t)arg[0]))p->last_error=6u;
        return 1;
    }
    if(!add&&!find)return 0;
    error=win_atom_selector(p,arg[0],win_suffix(name,"W"),s,&integer);
    if(error){
        p->last_error=error;
        return 1;
    }
    atom=integer?integer:add?win_atom_add_name(p,s):win_atom_find_name(p,s);
    if(!atom&&!add)p->last_error=2u;
    *result=atom;
    return 1;
}
static void win_window_properties_release(xxemul_windows *p,win_gui_object *o)
{
    size_t i;
    if(!o->properties)return;
    for(i=0;i<WIN_WINDOW_PROPERTIES;i++)if(o->properties[i].active&&o->properties[i].owns_atom)win_atom_delete(p,o->properties[i].atom);
    free(o->properties);
    o->properties=NULL;
}
