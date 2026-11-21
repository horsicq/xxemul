/* Bounded guest window lifecycle. Callbacks run through the normal instruction
 * engine; queued input never substitutes a branch or a callback result. */
static xxemul_status win_thread_yield(xxemul_windows *, xxemul_step_info *);
static uint64_t win_window_handle(xxemul_windows *p, const win_gui_object *o)
{ return UINT64_C(0x10000) + (uint64_t)(o - p->gui_objects); }
static win_gui_object *win_window_at(xxemul_windows *p, uint64_t h)
{ win_gui_object *o=win_gui_at(p,h); return o&&o->kind==WIN_GUI_WINDOW?o:NULL; }
static win_gui_object *win_hwnd_at(xxemul_windows *p, uint64_t h)
{
    win_gui_object *o=win_gui_at(p,h);
    return o&&(o->kind==WIN_GUI_WINDOW||o->kind==WIN_GUI_DIALOG||o->kind==WIN_GUI_CONTROL)?o:NULL;
}
static win_gui_object *win_window_frame_object(xxemul_windows *p,const win_window_frame *f)
{
    win_gui_object *o=win_hwnd_at(p,f->handle);
    return o&&o->generation==f->object_generation?o:NULL;
}
static win_window_frame *win_window_current(xxemul_windows *p)
{
    win_window_frame *f=NULL; size_t i; uint32_t id=p->threads[p->thread_current].id;
    for(i=0;i<WIN_WINDOW_FRAMES;i++)if(p->window_frames[i].active&&p->window_frames[i].owner_id==id&&(!f||p->window_frames[i].sequence>f->sequence))f=&p->window_frames[i];
    return f;
}
static win_window_frame *win_window_request(xxemul_windows *p,uint64_t h,unsigned operation)
{
    size_t i; win_gui_object *o=win_hwnd_at(p,h); win_window_frame *f;
    if(!o)return NULL;
    if(p->window_sequence==UINT64_MAX){p->last_error=8u;return NULL;}
    for(i=0;i<WIN_WINDOW_FRAMES&&p->window_frames[i].active;i++){}
    if(i==WIN_WINDOW_FRAMES){p->last_error=8u;return NULL;}
    f=&p->window_frames[i];memset(f,0,sizeof(*f));f->active=1;f->operation=(uint8_t)operation;f->handle=h;f->procedure=o->procedure;f->object_generation=o->generation;
    f->owner_id=p->threads[p->thread_current].id;f->sequence=++p->window_sequence;p->window_pending=(unsigned)i+1u;return f;
}
static void win_menu_release(xxemul_windows *p,uint64_t h,unsigned depth)
{
    win_gui_object *o=win_gui_at(p,h);unsigned i;if(!o||o->kind!=WIN_GUI_MENU||depth>WIN_GUI_OBJECTS)return;
    for(i=0;i<o->menu_count;i++)if(o->menu_items[i].flags&0x10u)win_menu_release(p,o->menu_items[i].id,depth+1u);
    free(o->menu_items);memset(o,0,sizeof(*o));
}
static void win_window_release(xxemul_windows *p,uint64_t h)
{
    win_gui_object *o=win_hwnd_at(p,h);win_allocation *a;size_t i;if(!o)return;
    if(o->menu)win_menu_release(p,o->menu,0u);
    if(o->canvas){win_gui_object *b=win_gui_at(p,o->canvas);if(b&&b->kind==WIN_GUI_BITMAP){win_allocation *a=win_find_allocation(p,b->resource);if(a)a->active=0;memset(b,0,sizeof(*b));}}
    if(o->window_region){win_gui_object *r=win_gui_at(p,o->window_region);if(r&&r->kind==WIN_GUI_REGION){free(r->region_rects);memset(r,0,sizeof(*r));}}
    a=win_find_allocation(p,o->extra);if(a)a->active=0;
    {size_t dc;for(dc=0;dc<WIN_GUI_OBJECTS;dc++){win_gui_object *d=&p->gui_objects[dc];if(d->active&&d->kind==WIN_GUI_DC&&d->parent==h)memset(d,0,sizeof(*d));}}
    win_window_properties_release(p,o);
    memset(o,0,sizeof(*o));
    for(i=0;i<WIN_GUI_OBJECTS;i++){
        win_gui_object *font=&p->gui_objects[i];
        if(font->active&&font->kind==WIN_GUI_FONT&&font->parent==h)memset(font,0,sizeof(*font));
    }
    {size_t i=0;while(i<p->window_message_count){if(p->window_messages[i].handle==h){memmove(&p->window_messages[i],&p->window_messages[i+1u],(p->window_message_count-i-1u)*sizeof(p->window_messages[0]));--p->window_message_count;}else ++i;}}
}
/* CBT creation veto precedes all creation messages. Drop provisional descendants
 * and their host-owned resources without fabricating destroy notifications. */
static void win_window_discard_tree(xxemul_windows *p,uint64_t h,unsigned depth)
{
    size_t i;
    if(depth>WIN_GUI_OBJECTS)return;
    for(i=0;i<WIN_GUI_OBJECTS;i++){
        win_gui_object *o=&p->gui_objects[i];
        if(o->active&&(o->kind==WIN_GUI_WINDOW||o->kind==WIN_GUI_DIALOG||o->kind==WIN_GUI_CONTROL)&&o->parent==h)
            win_window_discard_tree(p,UINT64_C(0x10000)+i,depth+1u);
    }
    win_window_release(p,h);
}
/* Read/validate completely before committing host state. The immutable snapshot
 * is private metadata; a guest cannot change the admitted-field comparison. */
static xxemul_status win_window_cbt_apply(xxemul_windows *p,win_gui_object *o,uint64_t data,const uint8_t *initial,int wide)
{
    uint8_t cs[80],width=win_word_size(p->emulator);uint16_t title[256];
    unsigned off=width==8u?32u:16u,name_off=width==8u?56u:36u,class_off=width==8u?64u:40u;
    uint64_t name;size_t i;int32_t cx,cy;
    if(!win_read(p,data,cs,width==8u?80u:48u))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(memcmp(cs+width,initial+width,3u*width)||
       memcmp(cs+off+16u,initial+off+16u,4u)||
       memcmp(cs+class_off,initial+class_off,width))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    name=width==8u?win_le64(cs+name_off):win_le32(cs+name_off);
    memset(title,0,sizeof(title));
    if(name){
        uint64_t limit=width==8u?UINT64_MAX:UINT32_MAX;
        for(i=0;i<256u;i++){
            uint64_t ch,delta=i*(wide?2u:1u);
            if(name>limit||delta>limit-name)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if(!win_load(p,name+delta,(uint8_t)(wide?2u:1u),&ch))return XXEMUL_STATUS_ADDRESS_FAULT;
            title[i]=wide?(uint16_t)ch:win_reg_ansi((uint8_t)ch);
            if(!ch)break;
        }
        if(i==256u)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    cx=(int32_t)win_le32(cs+off+4u);cy=(int32_t)win_le32(cs+off);
    o->x=(int32_t)win_le32(cs+off+12u);o->y=(int32_t)win_le32(cs+off+8u);
    o->width=cx<0?0:cx;o->height=cy<0?0:cy;
    o->ex_style=win_le32(cs+(width==8u?72u:44u));
    memcpy(o->text,title,sizeof(title));
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_window_finish_result(xxemul_windows *p,win_window_frame *f,uint64_t result,xxemul_step_info *info)
{
    xxemul_x86_state caller=f->caller;uint8_t width=win_word_size(p->emulator);
    if(f->data){win_allocation *a=win_find_allocation(p,f->data);if(a)a->active=0;}
    (void)win_store(p,win_current_teb(p)+(width==8u?0x68u:0x34u),4u,p->last_error);
    memset(f,0,sizeof(*f));p->emulator->x86=caller;
    p->emulator->x86.gpr[0]=width==8u?result:(uint32_t)result;
    if(info)info->next_address=caller.ip;
    return XXEMUL_STATUS_OK;
}
static int win_window_post(xxemul_windows *p,uint64_t h,uint32_t msg,uint64_t wp,uint64_t lp)
{
    win_gui_object *o=h?win_hwnd_at(p,h):NULL;win_window_message *m;size_t i;
    uint32_t owner=o?o->owner_id:p->threads[p->thread_current].id;
    if(h&&!o){p->last_error=1400u;return 0;}
    if(p->window_message_count==WIN_WINDOW_MESSAGES){p->last_error=1816u;return 0;}
    m=&p->window_messages[p->window_message_count++];m->handle=h;m->generation=o?o->generation:0u;m->message=msg;m->wparam=wp;m->lparam=lp;m->owner_id=owner;m->time=(uint32_t)p->scheduler_tick;
    for(i=0;i<WIN_MAX_THREADS;i++)if(p->threads[i].id==owner){++p->window_waits[i].generation;win_handle *e=win_handle_at(p,p->window_waits[i].event);if(e)e->signaled=1u;}
    win_dialog_signal_message(p,h);
    return 1;
}
static xxemul_status win_dialog_default_message(xxemul_windows *p,uint64_t handle,uint64_t generation,
    uint32_t message,uint64_t wp,uint64_t lp,int wide,uint64_t *result)
{
    win_gui_object *o=win_hwnd_at(p,handle);
    *result=0u;
    if(!o||o->kind!=WIN_GUI_DIALOG||o->generation!=generation)return XXEMUL_STATUS_OK;
    if(message==0x30u||message==0x31u)return win_gui_message(p,handle,message,wp,lp,wide,result);
    if(message==0x10u){
        /* The stock dialog procedure posts IDCANCEL/BN_CLICKED. The command
         * runs through the current WNDPROC only when the real queue is pumped.
         * Like the pinned Wine default, return zero even if PostMessage fails. */
        uint64_t cancel=win_gui_child(p,handle,2u);
        (void)win_window_post(p,handle,0x111u,2u,cancel);
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}
static int win_window_message_get(xxemul_windows *p,const uint64_t *arg,int remove,uint64_t *result)
{
    uint8_t width=win_word_size(p->emulator),out[48]={0};size_t size=width==8u?48u:28u,i;
    uint32_t owner=p->threads[p->thread_current].id,lo=(uint32_t)arg[2],hi=(uint32_t)arg[3];
    uint64_t thread_only=width==8u?UINT64_MAX:UINT32_MAX;win_window_wait *wait=&p->window_waits[p->thread_current];
    if(!win_memory_span(p,arg[0],size)){p->last_error=998u;*result=width==8u?UINT64_MAX:UINT32_MAX;return -1;}
    if(arg[1]&&arg[1]!=thread_only&&!win_hwnd_at(p,arg[1])){p->last_error=1400u;*result=width==8u?UINT64_MAX:UINT32_MAX;return -1;}
    wait->observed=wait->generation;
    for(i=0;i<=p->window_message_count;i++){
        win_window_message quit={0},*m;uint64_t h;
        if(i==p->window_message_count){if(!wait->quit_pending)break;quit.message=0x12u;quit.owner_id=owner;quit.wparam=wait->quit_code;m=&quit;}else m=&p->window_messages[i];h=m->handle;
        if(m->owner_id!=owner)continue;
        if(m->message!=0x12u){
            if(arg[1]==thread_only&&h)continue;
            if(arg[1]&&arg[1]!=thread_only){unsigned n=0;while(h&&h!=arg[1]&&n++<WIN_GUI_OBJECTS){win_gui_object *o=win_hwnd_at(p,h);h=o?o->parent:0;}if(h!=arg[1])continue;}
            if((lo||hi)&&(m->message<lo||m->message>hi))continue;
        }
        if(width==8u){win_put64(out,m->handle);win_put32(out+8u,m->message);win_put64(out+16u,m->wparam);win_put64(out+24u,m->lparam);win_put32(out+32u,m->time);}
        else{win_put32(out,(uint32_t)m->handle);win_put32(out+4u,m->message);win_put32(out+8u,(uint32_t)m->wparam);win_put32(out+12u,(uint32_t)m->lparam);win_put32(out+16u,m->time);}
        if(!win_write(p,arg[0],out,size)){p->last_error=998u;*result=UINT32_MAX;return -1;}
        *result=m->message==0x12u?0u:1u;
        if(remove){if(i==p->window_message_count)wait->quit_pending=0;else{memmove(m,m+1u,(p->window_message_count-i-1u)*sizeof(*m));--p->window_message_count;}}
        return 1;
    }
    return 0;
}
static xxemul_status win_window_wait_resume(xxemul_windows *p,xxemul_step_info *info)
{
    win_window_wait *w=&p->window_waits[p->thread_current];win_thread_context *t=&p->threads[p->thread_current];uint64_t value=0;int got;
    if(!w->active)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(w->wait_only){got=w->generation!=w->observed;value=1u;if(got)w->observed=w->generation;}
    else got=win_window_message_get(p,w->arguments,1,&value);
    if(got){p->emulator->x86=w->caller;p->emulator->x86.gpr[XXEMUL_X86_RAX]=value;w->active=0;t->blocked=0;if(info)info->next_address=w->caller.ip;return XXEMUL_STATUS_OK;}
    {win_handle *e=win_handle_at(p,w->event);size_t i;int others=0;if(e)e->signaled=0;
     for(i=0;i<WIN_MAX_THREADS;i++)if(i!=p->thread_current&&p->threads[i].active&&!p->threads[i].suspended)others=1;
     if(!others)return XXEMUL_STATUS_INPUT_REQUIRED;
     t->blocked=2;t->deadline=UINT64_MAX;t->wait_count=1;t->wait_handles[0]=w->event;t->wait_all=0;
     return win_thread_yield(p,info);}
}
static xxemul_status win_window_position_supported(xxemul_windows *p,uint32_t flags,int wide)
{
    /* A visibility-only request needs no move/size, Z-order or activation CBT
     * event. Other forms retain the existing current-thread hook boundary. */
    if(flags==0x17u||flags==0x57u||flags==0x97u)return XXEMUL_STATUS_OK;
    return win_cbt_event_supported(p,0,wide);
}
static int win_window_position_apply(xxemul_windows *p,win_window_frame *f)
{
    win_gui_object *o=win_window_frame_object(p,f);
    uint8_t width=win_word_size(p->emulator);
    uint64_t v;
    int32_t x,y,cx,cy;
    uint32_t flags;
    unsigned off=width*2u;
    if(!o){
        p->last_error=1400u;
        return 0;
    }
    if(!win_load(p,f->data+off,4u,&v))goto memory_fault;
    x=(int32_t)v;
    if(!win_load(p,f->data+off+4u,4u,&v))goto memory_fault;
    y=(int32_t)v;
    if(!win_load(p,f->data+off+8u,4u,&v))goto memory_fault;
    cx=(int32_t)v;
    if(!win_load(p,f->data+off+12u,4u,&v))goto memory_fault;
    cy=(int32_t)v;
    if(!win_load(p,f->data+off+16u,4u,&v))goto memory_fault;
    flags=(uint32_t)v;
    if(flags&~0x27ffu||(flags&0xc0u)==0xc0u||(!(flags&1u)&&(cx<0||cy<0))){
        p->last_error=87u;
        return 0;
    }
    if((flags&2u)||(x==o->x&&y==o->y))flags|=2u;
    if((flags&1u)||(cx==o->width&&cy==o->height))flags|=1u;
    if(!win_store(p,f->data+off+16u,4u,flags))goto memory_fault;
    if(!(flags&2u)){
        o->x=x;
        o->y=y;
    }
    if(!(flags&1u)){
        o->width=cx;
        o->height=cy;
    }
    if(flags&0x40u){
        o->visible=1;
        o->style|=0x10000000u;
    }
    if(flags&0x80u){
        o->visible=0;
        o->style&=~0x10000000u;
    }
    return 1;
    memory_fault:
    p->last_error=998u;
    return 0;
}
static xxemul_status win_window_invoke(xxemul_windows *p,win_window_frame *f,xxemul_step_info *info)
{
    xxemul *e=p->emulator;
    uint8_t width=win_word_size(e);
    uint64_t sp=(f->caller.gpr[XXEMUL_X86_RSP]&~UINT64_C(15))-(width==8u?40u:32u);
    uint64_t msg=f->message,wp=f->wparam,lp=f->lparam,callback_handle=f->handle;
    if((f->operation==1u||f->operation==2u)&&!f->cbt_state){
        win_gui_object *o=win_window_frame_object(p,f);xxemul_status status;
        unsigned code=f->operation==1u?3u:4u;
        if(!o)return win_window_finish_result(p,f,f->operation==2u?f->result:0u,info);
        status=win_cbt_event_supported(p,(int)code,f->cbt_wide);
        if(status!=XXEMUL_STATUS_OK)return status;
        f->cbt_state=1u;
        status=win_cbt_begin(p,(int)code,f->handle,f->operation==1u?f->data+96u:0u,f->cbt_wide,
                             1u,(unsigned)(f-p->window_frames),f->sequence,info);
        if(status!=XXEMUL_STATUS_OK&&f->active){
            xxemul_x86_state caller=f->caller;
            if(f->operation==1u&&win_window_frame_object(p,f))win_window_discard_tree(p,f->handle,0u);
            if(f->data){win_allocation *a=win_find_allocation(p,f->data);if(a)a->active=0u;}
            memset(f,0,sizeof(*f));e->x86=caller;e->x86.gpr[0]=0u;
        }
        return status;
    }
    if(f->operation==1u||f->operation==2u||f->operation==5u||f->operation==6u||f->operation==7u){
        win_gui_object *live=win_window_frame_object(p,f);
        if(!live)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        f->procedure=live->procedure;
    }
    if(f->operation==1u){
        msg=f->phase==0u?0x81u:f->phase==1u?0x83u:f->phase==2u?1u:f->phase==3u?2u:0x82u;
        wp=0;
        lp=f->phase==1u?f->data+80u:f->phase<3u?f->data:0;
    }
    else if(f->operation==2u){
        msg=f->phase==1u?2u:0x82u;
        wp=lp=0;
    }
    if((f->operation==1u&&f->phase==5u)||(f->operation==2u&&f->phase==0u)){
        win_gui_object *child=win_window_frame_object(p,f),*parent;
        if(!child)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!f->lparam)f->lparam=child->parent;
        parent=win_hwnd_at(p,f->lparam);
        if(!parent)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        callback_handle=f->lparam;
        f->procedure=parent->procedure;
        msg=0x210u;
        wp=(f->operation==1u?1u:2u)|((uint64_t)(child->id&0xffffu)<<16);
        lp=f->handle;
    }
    if(f->operation==5u||f->operation==7u){
        msg=f->phase?0x47u:0x46u;
        wp=0;
        lp=f->data;
    }
    else if(f->operation==6u){
        win_gui_object *o=win_window_frame_object(p,f);
        msg=f->phase?5u:3u;
        wp=0;
        lp=f->phase?((uint32_t)o->width&0xffffu)|(((uint32_t)o->height&0xffffu)<<16):((uint32_t)o->x&0xffffu)|(((uint32_t)o->y&0xffffu)<<16);
    }
    if(!win_store(p,sp,width,p->runtime_base+WIN_WINDOW_RETURN_OFFSET))return XXEMUL_STATUS_ADDRESS_FAULT;
    e->x86=f->caller;
    if(width==8u){
        e->x86.gpr[1]=callback_handle;
        e->x86.gpr[2]=msg;
        e->x86.gpr[8]=wp;
        e->x86.gpr[9]=lp;
    }
    else if(!win_store(p,sp+4u,4u,callback_handle)||!win_store(p,sp+8u,4u,msg)||!win_store(p,sp+12u,4u,wp)||!win_store(p,sp+16u,4u,lp))return XXEMUL_STATUS_ADDRESS_FAULT;
    f->call_sp=sp;
    e->x86.gpr[4]=sp;
    e->x86.ip=f->procedure;
    if(info)info->next_address=f->procedure;
    return XXEMUL_STATUS_OK;
}
static int win_window_notifies_parent(xxemul_windows *p,win_gui_object *o)
{
    return (o->style&0x40000000u)&&!(o->ex_style&4u)&&win_hwnd_at(p,o->parent);
}
static int win_window_notify_next(xxemul_windows *p,win_window_frame *f)
{
    win_gui_object *ancestor=win_hwnd_at(p,f->lparam);
    if(ancestor&&(ancestor->style&0x40000000u)&&win_hwnd_at(p,ancestor->parent)){
        f->lparam=ancestor->parent;
        return 1;
    }
    f->lparam=0;
    return 0;
}
static xxemul_status win_window_destroy_next(xxemul_windows *p,win_window_frame *parent,xxemul_step_info *info)
{
    size_t i;
    win_window_frame *child;
    win_gui_object *object;
    if(!win_window_frame_object(p,parent))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for(i=0;i<WIN_GUI_OBJECTS;i++){
        object=&p->gui_objects[i];
        if(!object->active||(object->kind!=WIN_GUI_WINDOW&&object->kind!=WIN_GUI_DIALOG&&object->kind!=WIN_GUI_CONTROL)||object->parent!=parent->handle)continue;
        if(object->destroying||++parent->message>WIN_GUI_OBJECTS)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        child=win_window_request(p,UINT64_C(0x10000)+i,2u);
        if(!child)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        p->window_pending=0;
        parent->phase=2u;
        object->destroying=1;
        child->phase=win_window_notifies_parent(p,object)?0u:1u;
        child->result=1u;
        child->cbt_state=2u; /* Implicit children do not repeat explicit DestroyWindow's CBT4. */
        child->caller=parent->caller;
        child->caller.ip=p->runtime_base+WIN_WINDOW_RETURN_OFFSET;
        return win_window_invoke(p,child,info);
    }
    parent->phase=3u;
    return win_window_invoke(p,parent,info);
}
/* Validate the bounded synchronous child tree before any destroy callback.
 * Cross-thread or owned top-level attachments, and starting a new ancestor
 * destruction from an independently destroying/creating child, are explicit
 * unsupported arrangements. Reentry into an already destroying ancestor is
 * harmless and handled by DestroyWindow's existing guard. */
static int win_window_destroy_tree_check(xxemul_windows *p,uint64_t handle,const win_window_frame *exclude)
{
    size_t i,j;
    unsigned active=0,max_depth=1;
    uint32_t owner=p->threads[p->thread_current].id;
    for(i=0;i<WIN_WINDOW_FRAMES;i++)if(p->window_frames[i].active && &p->window_frames[i]!=exclude)++active;
    for(i=0;i<WIN_GUI_OBJECTS;i++){
        win_gui_object *o=&p->gui_objects[i],*ancestor=o;
        unsigned depth=0;
        uint64_t child=UINT64_C(0x10000)+i;
        if(!o->active||(o->kind!=WIN_GUI_WINDOW&&o->kind!=WIN_GUI_DIALOG&&o->kind!=WIN_GUI_CONTROL)||child==handle)continue;
        while(ancestor&&ancestor->parent&&ancestor->parent!=handle&&depth<WIN_GUI_OBJECTS){
            ancestor=win_hwnd_at(p,ancestor->parent);
            ++depth;
        }
        if(!ancestor||ancestor->parent!=handle)continue;
        if(!(o->style&0x40000000u)||o->owner_id!=owner||o->destroying)return -1;
        for(j=0;j<WIN_WINDOW_FRAMES;j++)if(p->window_frames[j].active&&p->window_frames[j].handle==child&&p->window_frames[j].operation==1u)return -1;
        if(depth+2u>max_depth)max_depth=depth+2u;
    }
    return active+max_depth<=WIN_WINDOW_FRAMES?1:0;
}
static int win_window_destroy_tree(xxemul_windows *p,uint64_t handle)
{return win_window_destroy_tree_check(p,handle,NULL);}
static xxemul_status win_window_cbt_resume(xxemul_windows *p,unsigned slot,uint64_t sequence,uint64_t value,xxemul_step_info *info)
{
    win_window_frame *f;win_gui_object *o;uint8_t width=win_word_size(p->emulator);xxemul_status status;
    if(slot>=WIN_WINDOW_FRAMES)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    f=&p->window_frames[slot];
    if(!f->active||f->sequence!=sequence||f->owner_id!=p->threads[p->thread_current].id||
       f->cbt_state!=1u||(f->operation!=1u&&f->operation!=2u))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    o=win_window_frame_object(p,f);f->cbt_state=2u;
    if(f->operation==1u){
        uint64_t pcs,insert;uint8_t rectangle[16]={0};
        if(!o)return win_window_finish_result(p,f,0u,info);
        if(value){win_window_discard_tree(p,f->handle,0u);return win_window_finish_result(p,f,0u,info);}
        if(!win_load(p,f->data+96u,width,&pcs)||!win_load(p,f->data+96u+width,width,&insert))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if(pcs!=f->data||insert)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!xxemul_windows_memory_access(p,f->data+80u,sizeof(rectangle),1u,1))return XXEMUL_STATUS_ADDRESS_FAULT;
        status=win_window_cbt_apply(p,o,f->data,f->create_initial,f->cbt_wide);
        if(status!=XXEMUL_STATUS_OK)return status;
        win_put32(rectangle+8u,(uint32_t)o->width);win_put32(rectangle+12u,(uint32_t)o->height);
        if(!win_write(p,f->data+80u,rectangle,sizeof(rectangle)))return XXEMUL_STATUS_ADDRESS_FAULT;
    }else{
        int tree;
        if(!o)return win_window_finish_result(p,f,f->result,info);
        if(value)return win_window_finish_result(p,f,0u,info);
        tree=win_window_destroy_tree_check(p,f->handle,f);
        if(tree<0)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!tree){p->last_error=8u;return win_window_finish_result(p,f,0u,info);}
        o->destroying=1u;
        f->phase=win_window_notifies_parent(p,o)?0u:1u;
    }
    return win_window_invoke(p,f,info);
}
static xxemul_status win_window_return(xxemul_windows *p,xxemul_step_info *info)
{
    win_window_frame *f=win_window_current(p);
    xxemul *e=p->emulator;
    uint8_t width=win_word_size(e);
    uint64_t value=e->x86.gpr[0],result;
    unsigned i;
    static const unsigned nv32[]={
        3,5,6,7
    }
    ,nv64[]={
        3,5,6,7,12,13,14,15
    };
    if(f&&f->operation==2u&&f->phase==2u){
        if(e->x86.gpr[4]!=f->caller.gpr[4])return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!win_window_frame_object(p,f))return win_window_finish_result(p,f,f->result,info);
        return win_window_destroy_next(p,f,info);
    }
    if(!f||e->x86.gpr[4]!=f->call_sp+(width==8u?8u:20u))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for(i=0;i<(width==8u?8u:4u);i++){
        unsigned r=width==8u?nv64[i]:nv32[i];
        if(e->x86.gpr[r]!=f->caller.gpr[r])return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if(width==8u&&memcmp(e->x86.xmm[6],f->caller.xmm[6],10u*16u))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->operation==7u){
        /* The region transfer is committed before notification. A callback may
         * replace it or destroy the window; the outer frame never reinstalls it. */
        if(!f->phase&&win_window_at(p,f->handle)){
            f->phase=1u;
            return win_window_invoke(p,f,info);
        }
        result=1u;
    }
    else if(f->operation==5u){
        if(!win_window_frame_object(p,f)){
            p->last_error=1400u;
            result=0;
            goto finished;
        }
        if(!f->phase){
            win_gui_object *o=win_window_frame_object(p,f);uint64_t flags;xxemul_status status;
            if(!win_load(p,f->data+width*2u+16u,4u,&flags))return XXEMUL_STATUS_ADDRESS_FAULT;
            /* The real callback may edit WINDOWPOS or install a hook. Recheck
             * both before position_apply commits geometry or visibility. */
            status=win_window_position_supported(p,(uint32_t)flags,o->wide);
            if(status!=XXEMUL_STATUS_OK)return status;
            if(!win_window_position_apply(p,f)){
                result=0;
                goto finished;
            }
            f->phase=1;
            return win_window_invoke(p,f,info);
        }
        result=1;
    }
    else if(f->operation==6u){
        if(!f->phase&&!(f->result&1u)){
            f->phase=1;
            return win_window_invoke(p,f,info);
        }
        result=0;
    }
    else if(f->operation==1u){
        if(!win_window_frame_object(p,f)){
            f->failed=1;
            result=0;
            goto finished;
        }
        if(f->phase==5u&&win_window_notify_next(p,f))return win_window_invoke(p,f,info);
        if(f->phase==0u&&!value){
            win_window_frame_object(p,f)->destroying=1;
            f->failed=1;
            f->operation=2u;
            f->cbt_state=2u;
            f->result=0;
            f->phase=2u;
            return win_window_destroy_next(p,f,info);
        }
        if(f->phase==2u&&(width==8u?value==UINT64_MAX:(uint32_t)value==UINT32_MAX)){
            win_window_frame_object(p,f)->destroying=1;
            f->failed=1;
            f->operation=2u;
            f->cbt_state=2u;
            f->result=0;
            f->phase=1u;
            return win_window_invoke(p,f,info);
        }
        if(f->phase<2u||f->phase==3u){
            ++f->phase;
            return win_window_invoke(p,f,info);
        }
        if(!f->failed&&f->phase==2u&&win_window_notifies_parent(p,win_window_frame_object(p,f))){
            f->phase=5u;
            return win_window_invoke(p,f,info);
        }
        result=f->failed?0u:f->handle;
        if(f->failed){
            win_window_release(p,f->handle);
            p->last_error=1407u;
        }
    }
    else if(f->operation==2u){
        if(!win_window_frame_object(p,f)){
            result=f->result;
            goto finished;
        }
        if(f->phase==0u){
            if(win_window_notify_next(p,f))return win_window_invoke(p,f,info);
            f->phase=1u;
            return win_window_invoke(p,f,info);
        }
        if(f->phase==1u)return win_window_destroy_next(p,f,info);
        result=f->result;
        win_window_release(p,f->handle);
        if(f->failed)p->last_error=1407u;
    }
    else if(f->operation==8u){
        if(!value){
            result=f->result;
            if(f->message==0x10u||f->message==0x30u||f->message==0x31u){
                win_gui_object *o=win_window_frame_object(p,f);xxemul_status status;
                if(!o)return win_window_finish_result(p,f,0u,info);
                status=win_dialog_default_message(p,f->handle,f->object_generation,(uint32_t)f->message,f->wparam,f->lparam,o->wide,&result);
                if(status!=XXEMUL_STATUS_OK)return status;
            }
        }
        else if(!f->fixed_result)result=value;
        else{
            win_gui_object *o=win_window_frame_object(p,f);
            if(!o||!o->extra)return win_window_finish_result(p,f,0u,info);
            if(!win_load(p,o->extra,width,&result))return XXEMUL_STATUS_ADDRESS_FAULT;
        }
    }
    else result=f->operation==4u?((uint32_t)value!=0u):f->fixed_result?f->result:value;
    finished:
    return win_window_finish_result(p,f,result,info);
}
static int win_window_call(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    uint8_t width=win_word_size(p->emulator);win_gui_object *o;win_window_frame *f;size_t i;
    *status=XXEMUL_STATUS_OK;
    if(win_equal(name,"SetWindowPos")){
        uint32_t flags=(uint32_t)arg[6];uint8_t pos[40]={0};unsigned off=width*2u;o=win_hwnd_at(p,arg[0]);
        if(!o||o->owner_id!=p->threads[p->thread_current].id){p->last_error=1400u;return 1;}
        *status=win_window_position_supported(p,flags,o->wide);if(*status!=XXEMUL_STATUS_OK)return 1;
        if(flags&~0x27ffu||(flags&0xc0u)==0xc0u||(!(flags&1u)&&((int32_t)arg[4]<0||(int32_t)arg[5]<0))){p->last_error=87u;return 1;}
        /* Stored geometry/visibility and callbacks are supported; activation,
         * Z-order and repaint scheduling remain outside the headless profile. */
        if(!(flags&4u)&&arg[1]&&arg[1]!=1u&&arg[1]!=(width==8u?UINT64_MAX:UINT32_MAX)&&arg[1]!=(width==8u?UINT64_MAX-1u:UINT32_MAX-1u)&&!win_hwnd_at(p,arg[1])){p->last_error=1400u;return 1;}
        f=win_window_request(p,arg[0],5u);if(!f)return 1;f->data=win_heap_alloc(p,width==8u?40u:28u);if(!f->data){memset(f,0,sizeof(*f));p->window_pending=0;p->last_error=8u;return 1;}win_find_allocation(p,f->data)->heap_owner=UINT64_MAX;
        if(width==8u){win_put64(pos,arg[0]);win_put64(pos+8u,arg[1]);}else{win_put32(pos,(uint32_t)arg[0]);win_put32(pos+4u,(uint32_t)arg[1]);}
        win_put32(pos+off,(uint32_t)(flags&2u?o->x:(int32_t)arg[2]));win_put32(pos+off+4u,(uint32_t)(flags&2u?o->y:(int32_t)arg[3]));win_put32(pos+off+8u,(uint32_t)(flags&1u?o->width:(int32_t)arg[4]));win_put32(pos+off+12u,(uint32_t)(flags&1u?o->height:(int32_t)arg[5]));win_put32(pos+off+16u,flags);
        if(!win_write(p,f->data,pos,width==8u?40u:28u)){win_find_allocation(p,f->data)->active=0;memset(f,0,sizeof(*f));p->window_pending=0;*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        if(flags&0x400u){if(!win_window_position_apply(p,f)){win_find_allocation(p,f->data)->active=0;memset(f,0,sizeof(*f));p->window_pending=0;return 1;}f->phase=1;}return 1;
    }
    if(win_equal(name,"CreateWindowExA")||win_equal(name,"CreateWindowExW")){
        uint32_t error;int wide=win_suffix(name,"W");win_gui_class *c=win_gui_class_find(p,arg[10],arg[1],wide,&error);uint64_t h;uint8_t cs[112]={0};unsigned off;
        if(!c){p->last_error=error;return 1;}
        if(arg[8]&&!win_hwnd_at(p,arg[8])){p->last_error=1400u;return 1;}
        if(arg[8]&&win_hwnd_at(p,arg[8])->owner_id!=p->threads[p->thread_current].id){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
        if(p->emulator->arch!=XXEMUL_ARCH_X86){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
        *status=win_cbt_event_supported(p,3,wide);if(*status!=XXEMUL_STATUS_OK)return 1;
        *status=win_cbt_event_supported(p,3,c->wide);if(*status!=XXEMUL_STATUS_OK)return 1;
        h=win_gui_new(p,WIN_GUI_WINDOW,arg[8]);if(!h){p->last_error=8u;return 1;}o=win_window_at(p,h);
        if(!win_gui_text(p,arg[2],win_suffix(name,"W"),o->text)){memset(o,0,sizeof(*o));*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        memcpy(o->class_name,c->name,sizeof(c->name));o->class_ordinal=c->atom;o->class_style=c->style;o->procedure=c->procedure;o->instance=arg[10];o->owner_id=p->threads[p->thread_current].id;
        o->style=(uint32_t)arg[3];o->ex_style=(uint32_t)arg[0];o->wide=c->wide;o->menu=(o->style&0x40000000u)?0u:arg[9];o->id=(o->style&0x40000000u)?(uint32_t)arg[9]:0u;o->x=(int32_t)arg[4]==INT32_MIN?0:(int32_t)arg[4];o->y=(int32_t)arg[5]==INT32_MIN?0:(int32_t)arg[5];
        o->width=(int32_t)arg[6]==INT32_MIN?640:(int32_t)arg[6];o->height=(int32_t)arg[7]==INT32_MIN?480:(int32_t)arg[7];o->visible=(o->style&0x10000000u)!=0;
        if(o->width<0||o->height<0){memset(o,0,sizeof(*o));p->last_error=87u;return 1;}
        if(c->window_extra){o->extra=win_heap_alloc(p,c->window_extra);if(!o->extra){win_window_release(p,h);p->last_error=8u;return 1;}memset(p->emulator->region_data+(size_t)(o->extra-p->emulator->region_address),0,c->window_extra);win_find_allocation(p,o->extra)->heap_owner=UINT64_MAX;}
        f=win_window_request(p,h,1u);if(!f){win_window_release(p,h);return 1;}f->data=win_heap_alloc(p,sizeof(cs));if(!f->data){memset(f,0,sizeof(*f));p->window_pending=0;win_window_release(p,h);p->last_error=8u;return 1;}
        win_find_allocation(p,f->data)->heap_owner=UINT64_MAX;
        if(width==8u){win_put64(cs,arg[11]);win_put64(cs+8,arg[10]);win_put64(cs+16,arg[9]);win_put64(cs+24,arg[8]);off=32;}else{win_put32(cs,(uint32_t)arg[11]);win_put32(cs+4,(uint32_t)arg[10]);win_put32(cs+8,(uint32_t)arg[9]);win_put32(cs+12,(uint32_t)arg[8]);off=16;}
        win_put32(cs+off,(uint32_t)o->height);win_put32(cs+off+4,(uint32_t)o->width);win_put32(cs+off+8,(uint32_t)o->y);win_put32(cs+off+12,(uint32_t)o->x);win_put32(cs+off+16,o->style);
        if(width==8u){win_put64(cs+56,arg[2]);win_put64(cs+64,arg[1]);win_put32(cs+72,(uint32_t)arg[0]);}else{win_put32(cs+36,(uint32_t)arg[2]);win_put32(cs+40,(uint32_t)arg[1]);win_put32(cs+44,(uint32_t)arg[0]);}
        win_put32(cs+88,(uint32_t)o->width);win_put32(cs+92,(uint32_t)o->height);
        memcpy(f->create_initial,cs,width==8u?80u:48u);f->cbt_wide=(uint8_t)wide;
        if(width==8u)win_put64(cs+96u,f->data);else win_put32(cs+96u,(uint32_t)f->data);
        if(!win_write(p,f->data,cs,sizeof(cs))){win_find_allocation(p,f->data)->active=0;memset(f,0,sizeof(*f));p->window_pending=0;win_window_release(p,h);*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}*result=h;return 1;
    }
    if(win_equal(name,"DestroyWindow")||(win_prefix(name,"DefWindowProc")&&(uint32_t)arg[1]==0x10u)){
        o=win_hwnd_at(p,arg[0]);if(!o||o->owner_id!=p->threads[p->thread_current].id){p->last_error=1400u;return 1;}
        if(o->destroying){*result=1;return 1;}
        {int tree=win_window_destroy_tree(p,arg[0]);if(tree<0){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}if(!tree){p->last_error=8u;return 1;}}
        *status=win_cbt_event_supported(p,4,o->wide);if(*status!=XXEMUL_STATUS_OK)return 1;
        f=win_window_request(p,arg[0],2u);if(f){f->cbt_wide=o->wide;f->phase=win_window_notifies_parent(p,o)?0u:1u;f->result=win_equal(name,"DestroyWindow")?1u:0u;*result=f->result;}return 1;
    }
    if(win_prefix(name,"DefWindowProc")&&(uint32_t)arg[1]==0x47u){
        uint64_t flags;o=win_hwnd_at(p,arg[0]);if(!o){p->last_error=1400u;return 1;}
        if(!win_load(p,arg[3]+width*2u+16u,4u,&flags)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        if((flags&3u)!=3u){f=win_window_request(p,arg[0],6u);if(f){f->result=flags;f->phase=(flags&2u)?1u:0u;}}return 1;
    }
    if(win_prefix(name,"DefWindowProc")){
        o=win_hwnd_at(p,arg[0]);if(!o){p->last_error=1400u;return 1;}if((uint32_t)arg[1]==0x81u)*result=1u;
        else if((uint32_t)arg[1]==0xcu||(uint32_t)arg[1]==0xdu||(uint32_t)arg[1]==0xeu)return (*status=win_gui_message(p,arg[0],(uint32_t)arg[1],arg[2],arg[3],win_suffix(name,"W"),result)),1;
        return 1;
    }
    if(win_equal(name,"ShowWindow")||win_equal(name,"UpdateWindow")){
        o=win_hwnd_at(p,arg[0]);if(!o){p->last_error=1400u;return 1;}*result=win_equal(name,"ShowWindow")?o->visible:1u;
        if(win_equal(name,"ShowWindow")){*status=win_cbt_event_supported(p,5,o->wide);if(*status!=XXEMUL_STATUS_OK)return 1;}
        if(win_equal(name,"ShowWindow")){int visible=(uint32_t)arg[1]!=0u;if(visible==o->visible)return 1;o->visible=(uint8_t)visible;if(visible)o->style|=0x10000000u;else o->style&=~0x10000000u;}
        f=win_window_request(p,arg[0],3u);if(f){f->message=win_equal(name,"ShowWindow")?0x18u:0xfu;f->wparam=win_equal(name,"ShowWindow")?o->visible:0;f->fixed_result=1;f->result=*result;}return 1;
    }
    if(win_equal(name,"PostMessageA")||win_equal(name,"PostMessageW")){*result=win_window_post(p,arg[0],(uint32_t)arg[1],arg[2],arg[3]);return 1;}
    if(win_equal(name,"PostQuitMessage")){win_window_wait *w=&p->window_waits[p->thread_current];win_handle *event=win_handle_at(p,w->event);++w->generation;w->quit_pending=1;w->quit_code=(uint32_t)arg[0];if(event)event->signaled=1;return 1;}
    if(win_equal(name,"WaitMessage")){
        win_window_wait *w=&p->window_waits[p->thread_current];if(w->generation!=w->observed){w->observed=w->generation;*result=1;return 1;}
        if(!w->event)w->event=win_create_sync(p,WIN_HANDLE_EVENT,1u,0u,0u);if(!w->event){p->last_error=8u;return 1;}w->wait_only=1;p->window_wait_pending=1;return 1;
    }
    if(win_equal(name,"GetMessageA")||win_equal(name,"GetMessageW")||win_equal(name,"PeekMessageA")||win_equal(name,"PeekMessageW")){
        int peek=win_prefix(name,"Peek"),got;if(peek&&(arg[4]&~UINT64_C(3))){p->last_error=87u;return 1;}
        got=win_window_message_get(p,arg,!peek||(arg[4]&1u),result);if(peek){if(got>0)*result=1;return 1;}if(got)return 1;
        {win_window_wait *w=&p->window_waits[p->thread_current];if(!w->event)w->event=win_create_sync(p,WIN_HANDLE_EVENT,1u,0u,0u);if(!w->event){*result=UINT32_MAX;return 1;}memcpy(w->arguments,arg,4u*sizeof(*arg));w->wait_only=0;p->window_wait_pending=1;}return 1;
    }
    if(win_equal(name,"DispatchMessageA")||win_equal(name,"DispatchMessageW")){
        uint64_t h,msg,wp,lp;if(!win_load(p,arg[0],width,&h)||!win_load(p,arg[0]+(width==8u?8u:4u),4u,&msg)||!win_load(p,arg[0]+(width==8u?16u:8u),width,&wp)||!win_load(p,arg[0]+(width==8u?24u:12u),width,&lp)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        if(!h||msg==0x12u)return 1;o=win_hwnd_at(p,h);if(!o||o->owner_id!=p->threads[p->thread_current].id){p->last_error=1400u;return 1;}
        f=win_window_request(p,h,3u);if(f){f->message=msg;f->wparam=wp;f->lparam=lp;}return 1;
    }
    if(win_equal(name,"TranslateMessage")){
        uint64_t msg;if(!win_load(p,arg[0]+(width==8u?8u:4u),4u,&msg)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}if(msg>=0x100u&&msg<=0x109u)*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;
    }
    if(win_equal(name,"CreateMenu")||win_equal(name,"CreatePopupMenu")){*result=win_gui_new(p,WIN_GUI_MENU,0u);if(!*result)p->last_error=8u;return 1;}
    if(win_equal(name,"AppendMenuA")||win_equal(name,"AppendMenuW")){
        win_gui_object *sub=NULL;
        o=win_gui_at(p,arg[0]);if(!o||o->kind!=WIN_GUI_MENU){p->last_error=1401u;return 1;}if(arg[1]&~UINT64_C(0x813)){p->last_error=50u;return 1;}
        if(o->menu_count==32u){p->last_error=8u;return 1;}if(arg[1]&0x10u){uint64_t ancestor=arg[0];unsigned depth=0;sub=win_gui_at(p,arg[2]);while(ancestor&&ancestor!=arg[2]&&depth++<WIN_GUI_OBJECTS){win_gui_object *a=win_gui_at(p,ancestor);ancestor=a?a->parent:0;}if(!sub||sub->kind!=WIN_GUI_MENU||ancestor==arg[2]||sub->parent){p->last_error=1401u;return 1;}}
        if(!o->menu_items){o->menu_items=(win_menu_item*)calloc(32u,sizeof(*o->menu_items));if(!o->menu_items){p->last_error=8u;return 1;}}
        {win_menu_item *item=&o->menu_items[o->menu_count];if(!(arg[1]&0x800u)&&!win_gui_text(p,arg[3],win_suffix(name,"W"),item->text)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}item->id=arg[2];item->flags=(uint32_t)arg[1];if(sub)sub->parent=arg[0];++o->menu_count;}*result=1;return 1;
    }
    if(win_equal(name,"SetMenu")){o=win_hwnd_at(p,arg[0]);if(!o){p->last_error=1400u;return 1;}if(arg[1]){win_gui_object *m=win_gui_at(p,arg[1]);if(!m||m->kind!=WIN_GUI_MENU||(m->parent&&m->parent!=arg[0])){p->last_error=1401u;return 1;}}{win_gui_object *old=win_gui_at(p,o->menu);if(old&&old->kind==WIN_GUI_MENU)old->parent=0;}o->menu=arg[1];if(arg[1])win_gui_at(p,arg[1])->parent=arg[0];*result=1;return 1;}
    if(win_equal(name,"GetMenu")){o=win_hwnd_at(p,arg[0]);if(o)*result=o->menu;else p->last_error=1400u;return 1;}
    if(win_equal(name,"GetMenuItemCount")||win_equal(name,"GetMenuItemID")||win_equal(name,"GetMenuState")){
        o=win_gui_at(p,arg[0]);*result=UINT32_MAX;if(!o||o->kind!=WIN_GUI_MENU){p->last_error=1401u;return 1;}if(win_equal(name,"GetMenuItemCount")){*result=o->menu_count;return 1;}if(win_equal(name,"GetMenuState")&&!(arg[2]&0x400u)){for(i=0;i<o->menu_count;i++)if(o->menu_items[i].id==arg[1]){*result=o->menu_items[i].flags;break;}}else if(arg[1]<o->menu_count){win_menu_item *m=&o->menu_items[arg[1]];*result=win_equal(name,"GetMenuState")?m->flags:(m->flags&0x10u)?UINT32_MAX:(uint32_t)m->id;}return 1;
    }
    if(win_equal(name,"DestroyMenu")){o=win_gui_at(p,arg[0]);if(!o||o->kind!=WIN_GUI_MENU){p->last_error=1401u;return 1;}win_menu_release(p,arg[0],0u);*result=1;return 1;}
    return 0;
}
