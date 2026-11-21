/* Bounded headless dialogs. Templates are retained before callbacks; children
 * become visible to guest APIs only as their real creation phase starts. */
struct win_dialog_plan {
    win_gui_object items[65], font;
    uint64_t instance, parent;
    unsigned count, next;
    uint32_t creation_offset[65], creation_size[65], creation_used;
    uint8_t creation[0x10000];
    uint8_t has_font;
};
static xxemul_status win_dialog_create_next(xxemul_windows *,win_dialog_frame *,xxemul_step_info *);
static xxemul_status win_dialog_invoke(xxemul_windows *,win_dialog_frame *,xxemul_step_info *);
static xxemul_status win_dialog_return(xxemul_windows *,int,xxemul_step_info *);
static xxemul_status win_dialog_pump(xxemul_windows *,win_dialog_frame *,xxemul_step_info *);
static int win_dialog_contains(xxemul_windows *p,uint64_t root,uint64_t handle)
{
    unsigned depth=0;
    while(handle&&depth++<WIN_GUI_OBJECTS){win_gui_object *o;if(handle==root)return 1;o=win_hwnd_at(p,handle);if(!o)break;handle=o->parent;}
    return 0;
}
static void win_dialog_signal_message(xxemul_windows *p,uint64_t handle)
{
    unsigned i;for(i=0;i<WIN_GUI_DIALOGS;i++){win_dialog_frame *f=&p->dialogs[i];
        if(f->active&&!f->modeless&&win_dialog_contains(p,f->handle,handle)){win_handle *event=win_handle_at(p,f->event);if(event)event->signaled=1;}
    }
}
static win_dialog_frame *win_dialog_current(xxemul_windows *p)
{
    win_dialog_frame *best=NULL;size_t i;uint32_t id=p->threads[p->thread_current].id;
    for(i=0;i<WIN_GUI_DIALOGS;i++)if(p->dialogs[i].active&&p->dialogs[i].owner_id==id&&(!best||p->dialogs[i].sequence>best->sequence))best=&p->dialogs[i];
    return best;
}
static int win_dialog_rect(win_dialog_reader *r,win_gui_object *o)
{
    uint64_t v;int32_t *parts[]={&o->x,&o->y,&o->width,&o->height};unsigned i;
    for(i=0;i<4;i++){if(!win_dialog_value(r,2,&v))return 0;*parts[i]=(int16_t)v;}
    return o->width>=0&&o->height>=0;
}
static win_dialog_plan *win_dialog_parse(xxemul_windows *p,uint64_t address,uint32_t size,xxemul_status *status)
{
    win_dialog_reader r={p,address,address+size,XXEMUL_STATUS_OK};
    win_dialog_plan *plan=NULL;win_gui_object *o;uint64_t v,signature,extended,style,count;
    uint16_t menu[256],class_name[256],ordinal=0,face[256];unsigned i,j;
    *status=XXEMUL_STATUS_OK;
    if(!size||size>0x10000u||address>UINT64_MAX-size){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return NULL;}
    plan=(win_dialog_plan *)calloc(1,sizeof(*plan));if(!plan){p->last_error=8;return NULL;}
    if(!win_dialog_value(&r,2,&v)||!win_dialog_value(&r,2,&signature))goto bad;
    extended=v==1&&signature==0xffff;r.at=address;
    o=&plan->items[0];o->kind=WIN_GUI_DIALOG;
    if(extended){
        if(!win_dialog_value(&r,4,&v)||!win_dialog_value(&r,4,&v)||!win_dialog_value(&r,4,&v))goto bad;
        o->ex_style=(uint32_t)v;
        if(!win_dialog_value(&r,4,&style)||!win_dialog_value(&r,2,&count))goto bad;
    }else{
        if(!win_dialog_value(&r,4,&style)||!win_dialog_value(&r,4,&v))goto bad;
        o->ex_style=(uint32_t)v;
        if(!win_dialog_value(&r,2,&count))goto bad;
    }
    o->style=(uint32_t)style;plan->count=(unsigned)count+1u;
    if(count>64||!win_dialog_rect(&r,o)||!win_dialog_string(&r,menu,256,&ordinal)||menu[0]||ordinal||
       !win_dialog_string(&r,class_name,256,&ordinal)||class_name[0]||ordinal||!win_dialog_string(&r,o->text,256,NULL))goto bad;
    o->class_ordinal=0x8002;{static const uint16_t name[]={'#','3','2','7','7','0',0};memcpy(o->class_name,name,sizeof(name));}
    if(style&0x40u){
        uint64_t points,weight=400,italic=0,charset=1;
        if(!win_dialog_value(&r,2,&points))goto bad;
        if(extended&&(!win_dialog_value(&r,2,&weight)||!win_dialog_value(&r,1,&italic)||!win_dialog_value(&r,1,&charset)))goto bad;
        if(!win_dialog_string(&r,face,256,NULL))goto bad;
        plan->has_font=1;plan->font.kind=WIN_GUI_FONT;
        win_put32(plan->font.logfont,(uint32_t)(-(int32_t)((points*4+1)/3)));win_put32(plan->font.logfont+16,(uint32_t)weight);
        plan->font.logfont[20]=(uint8_t)italic;plan->font.logfont[23]=(uint8_t)charset;
        for(i=0;i<31&&face[i];i++){plan->font.logfont[28+i]=win_reg_unansi(face[i]);plan->font.text[i]=face[i];}
    }
    for(i=1;i<plan->count;i++){
        static const char *const builtin[]={"Button","Edit","Static","ListBox","ScrollBar","ComboBox"};
        r.at=(r.at+3)&~UINT64_C(3);o=&plan->items[i];o->kind=WIN_GUI_CONTROL;o->minimum=0;o->maximum=100;o->increment=10;
        if(extended&&!win_dialog_value(&r,4,&v))goto bad;
        if(!win_dialog_value(&r,4,&v))goto bad;
        if(extended){o->ex_style=(uint32_t)v;if(!win_dialog_value(&r,4,&style))goto bad;}
        else{style=v;if(!win_dialog_value(&r,4,&v))goto bad;
        o->ex_style=(uint32_t)v;}
        o->style=(uint32_t)style;
        if(!win_dialog_rect(&r,o)||!win_dialog_value(&r,extended?4:2,&v))goto bad;
        o->id=(uint32_t)v;
        if(!win_dialog_string(&r,o->class_name,256,&o->class_ordinal)||!win_dialog_string(&r,o->text,256,NULL)||!win_dialog_value(&r,2,&v))goto bad;
        if(v){
            uint64_t payload=v,total,limit=win_word_size(p->emulator)==4?UINT32_MAX:UINT64_MAX;
            if(!extended){if(v<2)goto bad;payload-=2;}
            total=payload+2;
            if(r.at>r.end||payload>r.end-r.at||total>sizeof(plan->creation)-plan->creation_used)goto bad;
            if(payload&&(r.at>limit||payload-1>limit-r.at)){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;goto bad;}
            plan->creation_offset[i]=plan->creation_used;plan->creation_size[i]=(uint32_t)total;
            win_put16(plan->creation+plan->creation_used,(uint16_t)v);
            if(payload&&!win_read(p,r.at,plan->creation+plan->creation_used+2,(size_t)payload)){*status=XXEMUL_STATUS_ADDRESS_FAULT;goto bad;}
            plan->creation_used+=(uint32_t)total;r.at+=payload;
        }
        if(o->class_ordinal){
            if(o->class_ordinal<0x80||o->class_ordinal>0x85)goto bad;
            for(j=0;builtin[o->class_ordinal-0x80][j];j++)o->class_name[j]=(uint8_t)builtin[o->class_ordinal-0x80][j];
            o->class_name[j]=0;
        }else{
            char name[256];for(j=0;j<255&&o->class_name[j];j++){if(o->class_name[j]>127)goto bad;name[j]=(char)o->class_name[j];}name[j]=0;
            if(!win_equal(name,"msctls_progress32")&&!win_equal(name,"static")&&!win_equal(name,"button")&&!win_equal(name,"edit")&&!win_equal(name,"listbox")&&!win_equal(name,"scrollbar")&&!win_equal(name,"combobox"))goto bad;
        }
    }
    return plan;
bad:
    if(r.status!=XXEMUL_STATUS_OK)*status=r.status;
    if(*status==XXEMUL_STATUS_OK)p->last_error=1813;
    free(plan);return NULL;
}
static void win_dialog_data_release(xxemul_windows *p,win_dialog_frame *f)
{
    win_allocation *a=win_find_allocation(p,f->data);if(a)a->active=0;f->data=0;
}
static xxemul_status win_dialog_finish(xxemul_windows *p,win_dialog_frame *f,xxemul_step_info *info)
{
    xxemul_x86_state caller=f->caller;uint64_t result=f->result;int retain=(f->modeless&&!f->ended)||f->teardown==3;
    if(f->ended&&f->established&&!f->teardown){
        win_gui_object *o=win_hwnd_at(p,f->handle);
        if(o&&o->generation==f->root_generation){
            win_window_frame *wf;int tree=win_window_destroy_tree(p,f->handle);
            if(tree<=0)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            wf=win_window_request(p,f->handle,2);if(!wf)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            p->window_pending=0;wf->caller=f->caller;wf->caller.ip=p->runtime_base+WIN_DIALOG_RETURN_OFFSET;
            wf->cbt_wide=o->wide;wf->phase=win_window_notifies_parent(p,o)?0:1;wf->result=1;
            f->teardown_slot=(uint32_t)(wf-p->window_frames);f->teardown_sequence=wf->sequence;
            f->phase=5;f->teardown=1;f->invoking=0;
            return win_window_invoke(p,wf,info);
        }
    }
    if(f->modeless&&!f->ended)result=f->handle;
    if(f->event)(void)win_close_handle(p,f->event);
    win_dialog_data_release(p,f);{win_allocation *a=win_find_allocation(p,f->filter_data);if(a)a->active=0;}
    if(!retain){win_gui_discard_owned(p,f->handle,f->root_generation);}
    free(f->plan);memset(f,0,sizeof(*f));
    p->emulator->x86=caller;p->emulator->x86.gpr[0]=win_word_size(p->emulator)==8?result:(uint32_t)result;
    if(info)info->next_address=caller.ip;
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_dialog_cs(xxemul_windows *p,win_dialog_frame *f,win_gui_object *o)
{
    uint8_t raw[1536]={0};uint8_t w=win_word_size(p->emulator);unsigned off=4*w,i;uint64_t cls=f->data+128,title=f->data+640;
    uint64_t head[]={f->plan->creation_size[f->plan->next]?f->data+1536:0,o->instance,o->kind==WIN_GUI_CONTROL?o->id:o->menu,o->parent};
    for(i=0;i<4;i++)if(w==8)win_put64(raw+i*w,head[i]);else win_put32(raw+i*w,(uint32_t)head[i]);
    win_put32(raw+off,(uint32_t)o->height);win_put32(raw+off+4,(uint32_t)o->width);win_put32(raw+off+8,(uint32_t)o->y);win_put32(raw+off+12,(uint32_t)o->x);win_put32(raw+off+16,o->style);
    off=w==8?56:36;
    if(w==8){win_put64(raw+off,title);win_put64(raw+off+w,cls);win_put64(raw+96,f->data);}
    else{win_put32(raw+off,(uint32_t)title);win_put32(raw+off+w,(uint32_t)cls);win_put32(raw+96,(uint32_t)f->data);}
    win_put32(raw+off+2*w,o->ex_style);
    for(i=0;i<256;i++){
        if(f->wide){win_put16(raw+128+i*2,o->class_name[i]);win_put16(raw+640+i*2,o->text[i]);}
        else{raw[128+i]=win_reg_unansi(o->class_name[i]);raw[640+i]=win_reg_unansi(o->text[i]);}
    }
    memcpy(f->create_initial,raw,w==8?80:48);
    if(!win_write(p,f->data,raw,sizeof(raw)))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(f->plan->creation_size[f->plan->next]&&!win_write(p,f->data+1536,
       f->plan->creation+f->plan->creation_offset[f->plan->next],f->plan->creation_size[f->plan->next]))return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_dialog_invoke(xxemul_windows *p,win_dialog_frame *f,xxemul_step_info *info)
{
    xxemul *e=p->emulator;win_gui_object *o=win_hwnd_at(p,f->phase==0?f->current_handle:f->phase==4?f->message_handle:f->handle);
    uint8_t w=win_word_size(e);uint64_t msg,wp=0,lp=0,sp;
    if(!o||(f->phase==0&&o->generation!=f->current_generation))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->phase==0){msg=f->create_phase==1?0x81:f->create_phase==2?0x83:1;lp=f->create_phase==2?f->data+80:f->data;}
    else if(f->phase==4){msg=f->message_id;wp=f->message_wparam;lp=f->message_lparam;}
    else{msg=f->phase==1?0x30:0x110;wp=f->phase==1?o->font:win_gui_initial_focus(p,f->handle);lp=f->phase==1?0:f->parameter;}
    if(!o->procedure)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->caller.gpr[4]<64)return XXEMUL_STATUS_ADDRESS_FAULT;
    sp=(f->caller.gpr[4]&~UINT64_C(15))-(w==8?40:32);
    if(!win_store(p,sp,w,p->runtime_base+WIN_DIALOG_RETURN_OFFSET))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(w==4&&(!win_store(p,sp+4,4,win_window_handle(p,o))||!win_store(p,sp+8,4,msg)||!win_store(p,sp+12,4,wp)||!win_store(p,sp+16,4,lp)))return XXEMUL_STATUS_ADDRESS_FAULT;
    e->x86=f->caller;if(w==8){e->x86.gpr[1]=win_window_handle(p,o);e->x86.gpr[2]=msg;e->x86.gpr[8]=wp;e->x86.gpr[9]=lp;}
    f->call_sp=sp;f->invoking=1;f->control=e->x87_control;f->mxcsr=e->x86_mxcsr;e->x86.gpr[4]=sp;e->x86.ip=o->procedure;
    if(info)info->next_address=e->x86.ip;
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_dialog_cbt_resume(xxemul_windows *p,unsigned slot,uint64_t seq,uint64_t value,xxemul_step_info *info)
{
    win_dialog_frame *f;win_gui_object *o;uint64_t cs,after;uint8_t rect[16]={0};xxemul_status status;
    if(slot>=WIN_GUI_DIALOGS)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    f=&p->dialogs[slot];
    if(!f->active||f->sequence!=seq||f->owner_id!=p->threads[p->thread_current].id||f->phase!=0)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    o=win_hwnd_at(p,f->current_handle);if(!o||o->generation!=f->current_generation){f->ended=1;f->result=f->modeless?0:(win_word_size(p->emulator)==8?UINT64_MAX:UINT32_MAX);return win_dialog_finish(p,f,info);}
    if(f->ended)return win_dialog_finish(p,f,info);
    if(value){
        if(f->plan->next)win_gui_discard_owned(p,f->current_handle,f->current_generation);
        f->ended=1;f->result=f->modeless?0:(win_word_size(p->emulator)==8?UINT64_MAX:UINT32_MAX);return win_dialog_finish(p,f,info);
    }
    if(!win_load(p,f->data+96,win_word_size(p->emulator),&cs)||!win_load(p,f->data+96+win_word_size(p->emulator),win_word_size(p->emulator),&after))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(cs!=f->data||after)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(!win_write(p,f->data+80,rect,sizeof(rect)))return XXEMUL_STATUS_ADDRESS_FAULT;
    status=win_window_cbt_apply(p,o,f->data,f->create_initial,f->wide);if(status!=XXEMUL_STATUS_OK)return status;
    win_put32(rect,(uint32_t)o->x);win_put32(rect+4,(uint32_t)o->y);win_put32(rect+8,(uint32_t)o->x+(uint32_t)o->width);win_put32(rect+12,(uint32_t)o->y+(uint32_t)o->height);
    if(!win_write(p,f->data+80,rect,sizeof(rect)))return XXEMUL_STATUS_ADDRESS_FAULT;
    f->create_phase=1;return win_dialog_invoke(p,f,info);
}
static xxemul_status win_dialog_create_next(xxemul_windows *p,win_dialog_frame *f,xxemul_step_info *info)
{
    win_dialog_plan *plan=f->plan;win_gui_object *o;uint64_t h,g;xxemul_status status;
    if(!plan||!f->active)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->ended)return win_dialog_finish(p,f,info);
    if(plan->next==1){
        win_gui_object *root=win_hwnd_at(p,f->handle);
        if(!root||root->generation!=f->root_generation){f->ended=1;f->result=f->modeless?0:(win_word_size(p->emulator)==8?UINT64_MAX:UINT32_MAX);return win_dialog_finish(p,f,info);}
        /* DefDlgProc receives creation messages before the application DLGPROC
         * is installed. Install it only after the root WM_CREATE returns. */
        if(!f->dlgproc_installed){
            if(!win_store(p,root->extra+win_word_size(p->emulator),win_word_size(p->emulator),f->procedure))return XXEMUL_STATUS_ADDRESS_FAULT;
            root->dialog_proc=f->procedure;f->dlgproc_installed=1;
        }
        if(plan->has_font&&!f->font_sent){f->font_sent=1;win_dialog_data_release(p,f);f->phase=1;return win_dialog_invoke(p,f,info);}
    }
    if(plan->next>=plan->count){win_dialog_data_release(p,f);f->phase=2;return win_dialog_invoke(p,f,info);}
    status=win_cbt_event_supported(p,3,f->wide);if(status!=XXEMUL_STATUS_OK)return status;
    win_dialog_data_release(p,f);o=&plan->items[plan->next];h=win_gui_new(p,o->kind,plan->next?f->handle:plan->parent);if(!h)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    o=win_gui_at(p,h);g=o->generation;*o=plan->items[plan->next];o->generation=g;o->active=1;o->wide=f->wide;o->owner_id=f->owner_id;o->instance=plan->instance;o->parent=plan->next?f->handle:plan->parent;o->visible=(o->style&0x10000000u)!=0;
    if(!plan->next){
        f->handle=h;f->root_generation=o->generation;o->dialog_proc=0;
        o->extra=win_heap_alloc(p,64);if(!o->extra)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;win_find_allocation(p,o->extra)->heap_owner=UINT64_MAX;
        {uint8_t raw[64]={0};if(win_word_size(p->emulator)==8)win_put64(raw+8,o->dialog_proc);else win_put32(raw+4,(uint32_t)o->dialog_proc);if(!win_write(p,o->extra,raw,64))return XXEMUL_STATUS_ADDRESS_FAULT;}
        if(plan->has_font){uint64_t font=win_gui_new(p,WIN_GUI_FONT,h);win_gui_object *fo=win_gui_at(p,font);if(!fo)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;g=fo->generation;*fo=plan->font;fo->generation=g;fo->parent=h;fo->active=1;o->font=font;}
    }else{o->font=win_gui_at(p,f->handle)->font;}
    o->procedure=win_resolve_entry(p,"user32.dll",o->kind==WIN_GUI_DIALOG?(f->wide?"DefDlgProcW":"DefDlgProcA"):(f->wide?"DefWindowProcW":"DefWindowProcA"),NULL);
    if(!o->procedure)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    f->current_handle=h;f->current_generation=o->generation;f->phase=0;f->create_phase=0;
    f->data=win_heap_alloc(p,1536+plan->creation_size[plan->next]);if(!f->data)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;win_find_allocation(p,f->data)->heap_owner=UINT64_MAX;
    status=win_dialog_cs(p,f,o);if(status!=XXEMUL_STATUS_OK)return status;
    return win_cbt_begin(p,3,h,f->data+96,f->wide,2,(unsigned)(f-p->dialogs),f->sequence,info);
}
static xxemul_status win_dialog_return(xxemul_windows *p,int waited,xxemul_step_info *info)
{
    win_dialog_frame *f=win_dialog_current(p);xxemul *e=p->emulator;uint8_t w=win_word_size(e);uint64_t value=e->x86.gpr[0];unsigned i;
    static const unsigned nv32[]={3,5,6,7},nv64[]={3,5,6,7,12,13,14,15};
    if(!f)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->phase==5&&f->teardown==1){
        if(e->x86.gpr[4]!=f->caller.gpr[4]||f->teardown_slot>=WIN_WINDOW_FRAMES||
           (p->window_frames[f->teardown_slot].active&&p->window_frames[f->teardown_slot].sequence==f->teardown_sequence))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        f->teardown=value?2:3;return win_dialog_finish(p,f,info);
    }
    if(!waited){
        if(!f->invoking||e->x86.gpr[4]!=f->call_sp+(w==8?8:20)||(e->x86.flags&0x400)||e->x87_control!=f->control||((e->x86_mxcsr^f->mxcsr)&~UINT32_C(0x3f)))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for(i=0;i<(w==8?8u:4u);i++){unsigned reg=w==8?nv64[i]:nv32[i];if(e->x86.gpr[reg]!=f->caller.gpr[reg])return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;}
        if(w==8&&memcmp(e->x86.xmm[6],f->caller.xmm[6],160))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        f->invoking=0;
    }
    e->x86=f->caller;if(f->ended)return win_dialog_finish(p,f,info);
    {win_gui_object *root=win_hwnd_at(p,f->handle),*current=win_hwnd_at(p,f->current_handle);
     if(!root||root->generation!=f->root_generation||(f->phase==0&&(!current||current->generation!=f->current_generation))){
         f->ended=1;f->result=f->modeless?0:(w==8?UINT64_MAX:UINT32_MAX);return win_dialog_finish(p,f,info);
     }}
    if(f->phase==0){
        if((f->create_phase==1&&!value)||(f->create_phase==3&&(w==8?value==UINT64_MAX:(uint32_t)value==UINT32_MAX))){f->ended=1;f->result=f->modeless?0:(w==8?UINT64_MAX:UINT32_MAX);return win_dialog_finish(p,f,info);}
        if(f->create_phase<3){++f->create_phase;return win_dialog_invoke(p,f,info);}
        if(!f->plan->next)f->established=1;
        ++f->plan->next;return win_dialog_create_next(p,f,info);
    }
    if(f->phase==1){f->phase=0;return win_dialog_create_next(p,f,info);}
    if(f->modeless)return win_dialog_finish(p,f,info);
    return win_dialog_pump(p,f,info);
}
static xxemul_status win_dialog_pump(xxemul_windows *p,win_dialog_frame *f,xxemul_step_info *info)
{
    xxemul *e=p->emulator;unsigned i;uint8_t w=win_word_size(e);uint32_t owner=p->threads[p->thread_current].id;
    if(f->ended)return win_dialog_finish(p,f,info);
    {win_gui_object *root=win_hwnd_at(p,f->handle);if(!root||root->generation!=f->root_generation){f->ended=1;f->result=0;return win_dialog_finish(p,f,info);}}
    if(p->window_waits[p->thread_current].quit_pending)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for(i=0;i<p->window_message_count;i++){
        win_window_message message=p->window_messages[i];uint8_t raw[48]={0};win_gui_object *o;
        if(message.owner_id!=owner||!win_dialog_contains(p,f->handle,message.handle))continue;
        {xxemul_status status=win_msgfilter_event_supported(p,0,f->wide);if(status!=XXEMUL_STATUS_OK)return status;}
        memmove(&p->window_messages[i],&p->window_messages[i+1],(--p->window_message_count-i)*sizeof(p->window_messages[0]));
        o=win_hwnd_at(p,message.handle);if(!o||(message.generation&&o->generation!=message.generation)){i=(unsigned)-1;continue;}
        f->message_handle=message.handle;f->message_generation=o->generation;f->message_id=message.message;f->message_wparam=message.wparam;f->message_lparam=message.lparam;
        if(!f->filter_data){f->filter_data=win_heap_alloc(p,64);if(!f->filter_data)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;win_find_allocation(p,f->filter_data)->heap_owner=UINT64_MAX;}
        if(w==8){win_put64(raw,message.handle);win_put32(raw+8,message.message);win_put64(raw+16,message.wparam);win_put64(raw+24,message.lparam);win_put32(raw+32,message.time);}
        else{win_put32(raw,(uint32_t)message.handle);win_put32(raw+4,message.message);win_put32(raw+8,(uint32_t)message.wparam);win_put32(raw+12,(uint32_t)message.lparam);win_put32(raw+16,message.time);}
        if(!win_write(p,f->filter_data,raw,w==8?48:28))return XXEMUL_STATUS_ADDRESS_FAULT;
        p->threads[p->thread_current].blocked=0;f->phase=3;
        return win_msgfilter_begin(p,0,0,f->filter_data,f->wide,3,(unsigned)(f-p->dialogs),f->sequence,info);
    }
    f->phase=3;e->x86.ip=p->runtime_base+WIN_DIALOG_WAIT_OFFSET;
    {win_handle *event=win_handle_at(p,f->event);if(event)event->signaled=0;}
    {win_thread_context *t=&p->threads[p->thread_current];int others=0;t->blocked=2;t->deadline=UINT64_MAX;t->wait_count=1;t->wait_handles[0]=f->event;t->wait_all=0;
     for(i=0;i<WIN_MAX_THREADS;i++)if(i!=p->thread_current&&p->threads[i].active&&!p->threads[i].suspended)others=1;
     if(!others)return XXEMUL_STATUS_INPUT_REQUIRED;
     return win_thread_yield(p,info);}
}
static xxemul_status win_dialog_filter_resume(xxemul_windows *p,unsigned slot,uint64_t seq,uint64_t value,xxemul_step_info *info)
{
    win_dialog_frame *f;win_gui_object *o;uint8_t raw[48],w=win_word_size(p->emulator);uint64_t handle;
    if(slot>=WIN_GUI_DIALOGS)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    f=&p->dialogs[slot];
    if(!f->active||f->owner_id!=p->threads[p->thread_current].id||f->sequence!=seq||f->phase!=3)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(f->ended)return win_dialog_finish(p,f,info);
    {win_gui_object *root=win_hwnd_at(p,f->handle);if(!root||root->generation!=f->root_generation){f->ended=1;f->result=0;return win_dialog_finish(p,f,info);}}
    if(value)return win_dialog_pump(p,f,info);
    if(!win_read(p,f->filter_data,raw,w==8?48:28))return XXEMUL_STATUS_ADDRESS_FAULT;
    handle=w==8?win_le64(raw):win_le32(raw);o=win_hwnd_at(p,handle);
    if(!o||!win_dialog_contains(p,f->handle,handle)||(handle==f->message_handle&&o->generation!=f->message_generation))return win_dialog_pump(p,f,info);
    f->message_handle=handle;f->message_generation=o->generation;f->message_id=win_le32(raw+w);f->message_wparam=w==8?win_le64(raw+16):win_le32(raw+8);f->message_lparam=w==8?win_le64(raw+24):win_le32(raw+12);
    f->phase=4;return win_dialog_invoke(p,f,info);
}
static int win_dialog_api(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    int modeless=win_equal(name,"CreateDialogIndirectParamA")||win_equal(name,"CreateDialogIndirectParamW");
    int indirect=modeless||win_equal(name,"DialogBoxIndirectParamA")||win_equal(name,"DialogBoxIndirectParamW");
    if(win_equal(name,"DefDlgProcA")||win_equal(name,"DefDlgProcW")){
        win_gui_object *o=win_hwnd_at(p,arg[0]);win_window_frame *wf;uint32_t message=(uint32_t)arg[1];uint64_t fallback=message==0x81?1:0;
        *status=XXEMUL_STATUS_OK;if(!o||o->kind!=WIN_GUI_DIALOG){p->last_error=1400;return 1;}
        if(message==0x83||message==1){*result=fallback;return 1;}
        if(!o->dialog_proc){
            if(message==0x10||message==0x30||message==0x31)*status=win_dialog_default_message(p,arg[0],o->generation,message,arg[2],arg[3],win_suffix(name,"W"),result);
            else *result=fallback;
            return 1;
        }
        if(!win_store(p,o->extra,win_word_size(p->emulator),0)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        wf=win_window_request(p,arg[0],8);if(!wf)return 1;wf->procedure=o->dialog_proc;wf->message=message;wf->wparam=arg[2];wf->lparam=arg[3];wf->result=fallback;
        wf->fixed_result=(uint8_t)!(message==0x110||message==0x39||message==0x2e||message==0x2f||message==0x37||(message>=0x132&&message<=0x138));
        return 1;
    }
    if(!indirect&&!win_equal(name,"DialogBoxParamA")&&!win_equal(name,"DialogBoxParamW"))return 0;
    {uint64_t address=arg[1],event=0;uint32_t size=0x10000;unsigned slot;win_dialog_plan *plan;win_dialog_frame *f;
     *status=XXEMUL_STATUS_OK;*result=modeless?0:(win_word_size(p->emulator)==8?UINT64_MAX:UINT32_MAX);
     if(p->emulator->arch!=XXEMUL_ARCH_X86){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
     if(arg[2]&&!win_hwnd_at(p,arg[2])){p->last_error=1400;*result=0;return 1;}
     if(!arg[3]||!win_memory_span(p,arg[3],1)){p->last_error=87;return 1;}
     if(!indirect){if(arg[0]&&arg[0]!=p->image_base){p->last_error=1812;return 1;}if(arg[1]>0xffff){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}if(!win_gui_resource(p,5,(unsigned)arg[1],&address,&size)){p->last_error=1814;return 1;}}
     *status=win_cbt_event_supported(p,3,win_suffix(name,"W"));if(*status!=XXEMUL_STATUS_OK)return 1;
     for(slot=0;slot<WIN_GUI_DIALOGS&&p->dialogs[slot].active;slot++){}if(slot==WIN_GUI_DIALOGS){p->last_error=8;return 1;}
     plan=win_dialog_parse(p,address,size,status);if(!plan)return 1;plan->instance=arg[0]?arg[0]:p->image_base;plan->parent=arg[2];
     if(!modeless){event=win_create_sync(p,WIN_HANDLE_EVENT,1,0,0);if(!event){free(plan);p->last_error=8;return 1;}}
     f=&p->dialogs[slot];memset(f,0,sizeof(*f));f->active=1;f->plan=plan;f->event=event;f->procedure=arg[3];f->parameter=arg[4];f->modeless=(uint8_t)modeless;f->wide=(uint8_t)win_suffix(name,"W");f->owner_id=p->threads[p->thread_current].id;f->sequence=++p->dialog_sequence;p->dialog_pending=slot+1;
     return 1;}
}
static xxemul_status win_cbt_creator_resume(xxemul_windows *p,unsigned kind,unsigned slot,uint64_t seq,uint64_t value,xxemul_step_info *info)
{
    if(kind==1)return win_window_cbt_resume(p,slot,seq,value,info);
    if(kind==2)return win_dialog_cbt_resume(p,slot,seq,value,info);
    if(kind==3)return win_dialog_filter_resume(p,slot,seq,value,info);
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}
