/* Window state/subclassing profile. Stored values are guest pointers; callback
 * execution uses the same asynchronous guest engine as creation/destruction. */
static int win_vcl_call(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    int set,ptr,wide=win_suffix(name,"W");
    uint8_t width=win_word_size(p->emulator);
    win_gui_object *o;
    size_t i;
    int32_t index;
    *status=XXEMUL_STATUS_OK;
    if(win_equal(name,"IsWindow")){
        *result=win_hwnd_at(p,arg[0])!=NULL;
        return 1;
    }
    if(win_equal(name,"VariantClear")){
        uint8_t variant[24],empty[2]={
            0
        };
        uint16_t type;
        size_t amount=width==8u?24u:16u;
        if(!arg[0]){
            *result=UINT32_C(0x80070057);
            return 1;
        }
        if(!win_read(p,arg[0],variant,amount)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        type=(uint16_t)(variant[0]|((uint16_t)variant[1]<<8));
        switch(type){
            case 0:case 1:case 2:case 3:case 4:case 5:case 6:case 7:case 10:case 11:case 14:
            case 16:case 17:case 18:case 19:case 20:case 21:case 22:case 23:
            /* Non-owning scalar values require only the documented vt reset;
                         * preserve every reserved/union byte and do not inspect payloads. */
            if(!win_write(p,arg[0],empty,sizeof(empty))){
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
            return 1;
            case 8:case 9:case 13:case 36:*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
            default:
            if(type&0x9000u){
                *result=UINT32_C(0x80020008);
                return 1;
            }
            if(type&0x6000u){
                *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                return 1;
            }
            *result=UINT32_C(0x80020008);
            return 1;
        }
    }
    if(win_equal(name,"GetParent")){
        o=win_hwnd_at(p,arg[0]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        *result=o->parent;
        return 1;
    }
    if(win_equal(name,"MulDiv")){
        int64_t a=(int32_t)arg[0],b=(int32_t)arg[1],den=(int32_t)arg[2],product=a*b;
        uint64_t magnitude,divisor,rounded;
        int negative;
        if(!den){
            *result=UINT32_MAX;
            return 1;
        }
        negative=(product<0)!=(den<0);
        magnitude=(uint64_t)(product<0?-product:product);
        divisor=(uint64_t)(den<0?-den:den);
        rounded=magnitude/divisor;
        if(magnitude%divisor>=(divisor+1u)/2u)++rounded;
        if(rounded>(negative?UINT64_C(2147483648):UINT64_C(2147483647)))*result=UINT32_MAX;
        else *result=(uint32_t)(negative?-(int64_t)rounded:(int64_t)rounded);
        return 1;
    }
    if(win_equal(name,"GetWindowRect")||win_equal(name,"GetClientRect")){
        uint8_t rect[16];
        int64_t x=0,y=0,right,bottom;
        o=win_hwnd_at(p,arg[0]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        if(win_equal(name,"GetWindowRect")){
            win_gui_object *parent=o;
            unsigned depth=0;
            while(parent){
                x+=parent->x;
                y+=parent->y;
                if(!parent->parent)break;
                parent=win_hwnd_at(p,parent->parent);
                if(++depth>WIN_GUI_OBJECTS){
                    p->last_error=87u;
                    return 1;
                }
            }
        }
        right=x+o->width;
        bottom=y+o->height;
        if(x<INT32_MIN||x>INT32_MAX||y<INT32_MIN||y>INT32_MAX||right<INT32_MIN||right>INT32_MAX||bottom<INT32_MIN||bottom>INT32_MAX){
            p->last_error=87u;
            return 1;
        }
        win_put32(rect,(uint32_t)x);
        win_put32(rect+4u,(uint32_t)y);
        win_put32(rect+8u,(uint32_t)right);
        win_put32(rect+12u,(uint32_t)bottom);
        if(!win_write(p,arg[1],rect,sizeof(rect))){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        *result=1;
        return 1;
    }
    if(win_equal(name,"IsWindowVisible")||win_equal(name,"IsWindowUnicode")||win_equal(name,"IsIconic")){
        o=win_hwnd_at(p,arg[0]);
        if(!o)return 1;
        if(win_equal(name,"IsWindowUnicode"))*result=o->wide;
        else if(win_equal(name,"IsIconic"))*result=(o->style&0x20000000u)!=0;
        else{
            win_gui_object *parent=o;
            unsigned depth=0;
            *result=1;
            while(parent){
                if(!parent->visible){
                    *result=0;
                    break;
                }
                if(!parent->parent)break;
                parent=win_hwnd_at(p,parent->parent);
                if(++depth>WIN_GUI_OBJECTS){
                    *result=0;
                    break;
                }
            }
        }
        return 1;
    }
    if((win_equal(name,"SystemParametersInfoA")||win_equal(name,"SystemParametersInfoW"))&&(uint32_t)arg[0]==0x30u){
        uint8_t rect[16]={
            0
        };
        if((uint32_t)arg[1]){
            p->last_error=87u;
            return 1;
        }
        win_put32(rect+8u,640u);
        win_put32(rect+12u,480u);
        if(!win_write(p,arg[2],rect,sizeof(rect))){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        *result=1;
        return 1;
    }
    if(win_equal(name,"MonitorFromWindow")){
        o=win_hwnd_at(p,arg[0]);
        if((uint32_t)arg[1]>2u){
            p->last_error=87u;
            return 1;
        }
        if((o&&o->x<640&&o->y<480&&(int64_t)o->x+o->width>0&&(int64_t)o->y+o->height>0)||(uint32_t)arg[1])*result=UINT64_C(0x40000001);
        return 1;
    }
    if(win_equal(name,"GetMonitorInfoA")||win_equal(name,"GetMonitorInfoW")){
        uint64_t size;
        uint8_t info[104]={
            0
        };
        const char device[]="\\\\.\\DISPLAY1";
        unsigned expected=wide?104u:72u;
        if(arg[0]!=UINT64_C(0x40000001)){
            p->last_error=1461u;
            return 1;
        }
        if(!win_load(p,arg[1],4u,&size)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        if(size!=40u&&size!=expected){
            p->last_error=87u;
            return 1;
        }
        win_put32(info,(uint32_t)size);
        win_put32(info+12u,640u);
        win_put32(info+16u,480u);
        win_put32(info+28u,640u);
        win_put32(info+32u,480u);
        win_put32(info+36u,1u);
        if(size!=40u)for(i=0;i<sizeof(device);i++)info[40u+i*(wide?2u:1u)]=(uint8_t)device[i];
        if(!win_write(p,arg[1],info,(size_t)size)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        *result=1;
        return 1;
    }
    if(win_equal(name,"EnumDisplayMonitors")){
        uint8_t rect[16]={
            0
        };
        int32_t left=0,top=0,right=640,bottom=480;
        win_window_frame *f=NULL;
        uint64_t value;
        if(p->emulator->arch!=XXEMUL_ARCH_X86){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        if(arg[0]){
            o=win_gui_at(p,arg[0]);
            if(!o||o->kind!=WIN_GUI_DC){
                p->last_error=6u;
                return 1;
            }
            /* DC clipping/coordinate transforms are not modeled. */*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        if(!arg[2]){
            p->last_error=87u;
            return 1;
        }
        if(arg[1]){
            int32_t bounds[4];
            for(i=0;i<4;i++){
                if(!win_load(p,arg[1]+i*4u,4u,&value)){
                    *status=XXEMUL_STATUS_ADDRESS_FAULT;
                    return 1;
                }
                bounds[i]=(int32_t)value;
            }
            if(bounds[0]>left)left=bounds[0];
            if(bounds[1]>top)top=bounds[1];
            if(bounds[2]<right)right=bounds[2];
            if(bounds[3]<bottom)bottom=bounds[3];
        }
        if(right<=left||bottom<=top){
            *result=1;
            return 1;
        }
        for(i=0;i<WIN_WINDOW_FRAMES;i++)if(!p->window_frames[i].active){
            f=&p->window_frames[i];
            break;
        }
        if(!f){
            p->last_error=8u;
            return 1;
        }
        memset(f,0,sizeof(*f));
        f->data=win_heap_alloc(p,sizeof(rect));
        if(!f->data){
            p->last_error=8u;
            return 1;
        }
        win_find_allocation(p,f->data)->heap_owner=UINT64_MAX;
        win_put32(rect,(uint32_t)left);
        win_put32(rect+4u,(uint32_t)top);
        win_put32(rect+8u,(uint32_t)right);
        win_put32(rect+12u,(uint32_t)bottom);
        if(!win_write(p,f->data,rect,sizeof(rect))){
            win_find_allocation(p,f->data)->active=0;
            memset(f,0,sizeof(*f));
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        f->active=1;
        f->operation=4;
        f->handle=UINT64_C(0x40000001);
        f->procedure=arg[2];
        f->message=arg[0];
        f->wparam=f->data;
        f->lparam=arg[3];
        f->owner_id=p->threads[p->thread_current].id;
        f->sequence=++p->window_sequence;
        p->window_pending=(unsigned)i+1u;
        return 1;
    }
    if(win_equal(name,"GetSystemMetrics")){
        /* Fixed96-DPI headless display:32px icons/16px small icons and17px
         * scrollbars/thumbs/arrows. These are configured profile dimensions,
         * not host measurements; no attached physical mouse is claimed. */
        switch((int32_t)arg[0]){
            case 0:case 78:*result=640u;
            break;
            case 1:case 79:*result=480u;
            break;
            case 76:case 77:*result=0u;
            break;
            /* Nominal classic dimensions at96DPI. These values do not
             * implement style-dependent client/nonclient geometry. */
            case 0x4:*result=19u;
            break;
            case 0x5:case 0x6:*result=1u;
            break;
            case 0x7:case 0x8:*result=3u;
            break;
            case 11:case 12:case 0xd:case 0xe:*result=32u;
            break;
            case 49:case 50:*result=16u;
            break;
            case 2:case 3:case 9:case 10:case 20:case 21:*result=17u;
            break;
            case 19:case 75:*result=0u;
            break;
            /* SM_DBCSENABLED: this fixed en-US/ACP1252 User32 profile
             * does not provide DBCS text support. Preserve last_error. */
            case 0x2a:*result=0u;
            break;
            case 80:case 81:*result=1u;
            break;
            default:*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        return 1;
    }
    if(win_equal(name,"GetDC")){
        uint64_t h;
        win_gui_class *c=NULL;
        o=arg[0]?win_hwnd_at(p,arg[0]):NULL;
        if(arg[0]&&!o){
            p->last_error=1400u;
            return 1;
        }
        if(o){
            for(i=0;i<WIN_GUI_CLASSES;i++)if(p->gui_classes[i].active&&p->gui_classes[i].atom==o->class_ordinal){
                c=&p->gui_classes[i];
                break;
            }
            /* Class/private DC attribute persistence is outside this common-DC profile. */
            if(c&&(c->style&0x60u)){
                *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                return 1;
            }
        }
        h=win_gui_new(p,WIN_GUI_DC,arg[0]);
        if(!h){
            p->last_error=8u;
            return 1;
        }
        o=win_gui_at(p,h);
        o->owner_id=p->threads[p->thread_current].id;
        o->icon[0]=0xffffffu;
        o->id=2u;
        *result=h;
        return 1;
    }
    if(win_equal(name,"ReleaseDC")){
        o=win_gui_at(p,arg[1]);
        if(!o||o->kind!=WIN_GUI_DC||o->style||o->parent!=arg[0]||o->owner_id!=p->threads[p->thread_current].id)return 1;
        memset(o,0,sizeof(*o));
        *result=1;
        return 1;
    }
    if(win_equal(name,"GetDeviceCaps")){
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_DC||o->owner_id!=p->threads[p->thread_current].id){
            p->last_error=6u;
            return 1;
        }
        /* Fixed headless raster-display profile: 640x480, 32-bit RGB, 96dpi.
                         * No drawing or accelerated capability is advertised. */
        switch((int32_t)arg[1]){
            case 0:*result=0x300u;
            break;
            case 2:*result=1u;
            break;
            case 4:*result=169u;
            break;
            case 6:*result=127u;
            break;
            case 8:case 110:case 118:*result=640u;
            break;
            case 10:case 111:case 117:*result=480u;
            break;
            case 12:case 108:*result=32u;
            break;
            case 14:*result=1u;
            break;
            case 16:case 18:case 24:*result=UINT32_MAX;
            break;
            case 20:case 22:case 26:case 28:case 30:case 32:case 34:case 36:
            case 104:case 106:case 112:case 113:case 114:case 115:case 119:case 120:*result=0u;
            break;
            case 38:*result=1u;
            break;
            case 40:case 42:*result=36u;
            break;
            case 44:*result=51u;
            break;
            case 88:case 90:*result=96u;
            break;
            case 116:*result=60u;
            break;
            default:*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        return 1;
    }
    if(win_equal(name,"GetClassNameA")||win_equal(name,"GetClassNameW")){
        uint8_t output[512];const uint16_t *text;size_t length=0,copied;
        int32_t capacity=(int32_t)arg[2];
        o=win_hwnd_at(p,arg[0]);
        if(!o){p->last_error=1400u;return 1;}
        if(capacity<=0){p->last_error=87u;return 1;}
        text=o->class_name;
        if(!text[0]){p->last_error=1411u;return 1;}
        while(length<256u&&text[length])++length;
        if(length==256u){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
        copied=length<(size_t)capacity?length:(size_t)capacity-1u;
        for(i=0;i<copied;i++){
            if(wide)win_put16(output+i*2u,text[i]);else output[i]=win_reg_unansi(text[i]);
        }
        if(wide)win_put16(output+copied*2u,0u);else output[copied]=0u;
        if(!win_write(p,arg[1],output,(copied+1u)*(wide?2u:1u))){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
        *result=copied;return 1;
    }
    if(win_equal(name,"SetPropA")||win_equal(name,"SetPropW")||win_equal(name,"GetPropA")||win_equal(name,"GetPropW")||win_equal(name,"RemovePropA")||win_equal(name,"RemovePropW")){
        uint16_t atom=0,s[256];
        uint32_t error=0;
        win_window_property *entry=NULL;
        size_t empty=WIN_WINDOW_PROPERTIES;
        int string=arg[1]>0xffffu,remove=win_prefix(name,"Remove");
        set=win_prefix(name,"Set");
        o=win_hwnd_at(p,arg[0]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        if(string){
            error=win_reg_name(p,arg[1],wide,s,256u,0);
            if(!error&&!s[0])error=87u;
            if(error){
                p->last_error=error;
                return 1;
            }
            atom=win_atom_find_name(p,s);
        }
        else{
            atom=(uint16_t)arg[1];
            if(!atom){
                p->last_error=87u;
                return 1;
            }
        }
        if(o->properties)for(i=0;i<WIN_WINDOW_PROPERTIES;i++){
            win_window_property *e=&o->properties[i];
            if(e->active&&e->atom==atom)entry=e;
            else if(!e->active&&empty==WIN_WINDOW_PROPERTIES)empty=i;
        }
        if(!set){
            if(entry){
                *result=entry->data;
                if(remove){
                    if(entry->owns_atom)win_atom_delete(p,entry->atom);
                    memset(entry,0,sizeof(*entry));
                }
            }
            return 1;
        }
        if(!entry&&o->properties&&empty==WIN_WINDOW_PROPERTIES){
            p->last_error=8u;
            return 1;
        }
        if(!string&&!win_atom_live(p,atom)){
            p->last_error=6u;
            return 1;
        }
        if(!o->properties){
            o->properties=(win_window_property*)calloc(WIN_WINDOW_PROPERTIES,sizeof(*o->properties));
            if(!o->properties){
                p->last_error=8u;
                return 1;
            }
            empty=0;
        }
        if(string){
            atom=win_atom_add_name(p,s);
            if(!atom)return 1;
        }
        if(!entry)entry=&o->properties[empty];
        else if(entry->owns_atom)win_atom_delete(p,entry->atom);
        entry->active=1;
        entry->atom=atom;
        entry->data=width==4u?(uint32_t)arg[2]:arg[2];
        entry->owns_atom=(uint8_t)string;
        *result=1;
        return 1;
    }
    if(win_prefix(name,"GetWindowLong")||win_prefix(name,"SetWindowLong")){
        uint64_t old=0,value=arg[2];
        win_gui_class *c=NULL;
        set=win_prefix(name,"Set");
        ptr=strstr(name,"Ptr")!=NULL;
        uint8_t bytes=ptr?width:4u;
        o=win_hwnd_at(p,arg[0]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        index=(int32_t)arg[1];
        c=win_gui_object_class(p,o);
        if(!ptr&&width==8u&&(index==-4||index==-6)){
            p->last_error=1413u;
            return 1;
        }
        if(index==-4)old=o->procedure;
        else if(index==-6)old=o->instance;
        else if(index==-21)old=o->user_data;
        else if(index==-16)old=o->style;
        else if(index==-20)old=o->ex_style;
        else if(o->kind==WIN_GUI_DIALOG&&index==(int32_t)width){
            if(!ptr&&width==8u){p->last_error=1413u;return 1;}
            old=o->dialog_proc;
            if(set){
                if(!o->extra||!win_store(p,o->extra+width,bytes,value)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
                o->dialog_proc=bytes==4u?(uint32_t)value:value;
            }
            *result=old;return 1;
        }
        else if(index>=0&&o->extra&&
                (uint32_t)index<=(o->kind==WIN_GUI_DIALOG?64u:c?c->window_extra:0u)&&
                bytes<=(o->kind==WIN_GUI_DIALOG?64u:c?c->window_extra:0u)-(uint32_t)index){
            if(!win_load(p,o->extra+(uint32_t)index,bytes,&old)){
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
            if(set&&!win_store(p,o->extra+(uint32_t)index,bytes,value)){
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
            *result=old;
            return 1;
        }
        else{
            p->last_error=1413u;
            return 1;
        }
        if(set){
            if(bytes==4u)value=(uint32_t)value;
            if(index==-4)o->procedure=value;
            else if(index==-6)o->instance=value;
            else if(index==-21)o->user_data=value;
            else if(index==-16)o->style=(uint32_t)value;
            else o->ex_style=(uint32_t)value;
        }
        *result=bytes==4u?(uint32_t)old:old;
        return 1;
    }
    if(win_prefix(name,"GetClassLong")||win_prefix(name,"SetClassLong")){
        win_gui_class *c=NULL;
        uint64_t old;
        set=win_prefix(name,"Set");
        ptr=strstr(name,"Ptr")!=NULL;
        o=win_hwnd_at(p,arg[0]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        c=win_gui_object_class(p,o);
        index=(int32_t)arg[1];
        if(index==-32){
            if(set)p->last_error=1413u;else *result=o->class_ordinal;
            return 1;
        }
        if(index==-26){
            old=c?c->style:o->class_style;
            if(set){
                if(c){
                    c->style=(uint32_t)arg[2];
                    for(i=0;i<WIN_GUI_OBJECTS;i++)if(p->gui_objects[i].active&&p->gui_objects[i].class_ordinal==c->atom)
                        p->gui_objects[i].class_style=c->style;
                }else{*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
            }
            *result=(uint32_t)old;return 1;
        }
        if(!c){p->last_error=1411u;return 1;}
        if(index!=-14){
            p->last_error=1413u;
            return 1;
        }
        old=c->icon;
        if(set)c->icon=ptr&&width==8u?arg[2]:(uint32_t)arg[2];
        *result=ptr&&width==8u?old:(uint32_t)old;
        return 1;
    }
    if(win_equal(name,"SendMessageA")||win_equal(name,"SendMessageW")){
        win_window_frame *f;
        o=win_hwnd_at(p,arg[0]);
        if(!o)return 0;
        if(p->emulator->arch!=XXEMUL_ARCH_X86||o->owner_id!=p->threads[p->thread_current].id){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        f=win_window_request(p,arg[0],3u);
        if(f){
            f->message=(uint32_t)arg[1];
            f->wparam=arg[2];
            f->lparam=arg[3];
        }
        return 1;
    }
    if(win_equal(name,"CallWindowProcA")||win_equal(name,"CallWindowProcW")){
        win_window_frame *f;
        o=win_hwnd_at(p,arg[1]);
        if(!o){
            p->last_error=1400u;
            return 1;
        }
        if(p->emulator->arch!=XXEMUL_ARCH_X86){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        f=win_window_request(p,arg[1],3u);
        if(f){
            f->procedure=arg[0];
            f->message=(uint32_t)arg[2];
            f->wparam=arg[3];
            f->lparam=arg[4];
        }
        return 1;
    }
    return 0;
}
