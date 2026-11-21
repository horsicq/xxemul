/* Owned DDB storage for the headless display profile, without a renderer. */
static uint32_t win_gdi_u32(const uint8_t *b)
{
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
static uint64_t win_gdi_bitmap(xxemul_windows *p,int32_t cx,int32_t cy,unsigned bpp)
{
    uint64_t count,data,h;
    uint32_t stride;
    win_gui_object *o;
    if(cx<=0||cy<=0||cx>8192||cy>8192){
        p->last_error=87u;
        return 0;
    }
    stride=(uint32_t)(((uint64_t)(uint32_t)cx*bpp+15u)/16u*2u);
    count=(uint64_t)stride*(uint32_t)cy;
    if(count>16u*1024u*1024u){
        p->last_error=8u;
        return 0;
    }
    h=win_gui_new(p,WIN_GUI_BITMAP,0u);
    if(!h){
        p->last_error=8u;
        return 0;
    }
    data=win_heap_alloc(p,count);
    if(!data){
        memset(win_gui_at(p,h),0,sizeof(*o));
        p->last_error=8u;
        return 0;
    }
    win_find_allocation(p,data)->heap_owner=UINT64_MAX;
    o=win_gui_at(p,h);
    o->resource=data;
    o->resource_size=(uint32_t)count;
    o->width=cx;
    o->height=cy;
    o->increment=(int32_t)stride;
    o->style=bpp;
    memset(p->emulator->region_data+(size_t)(data-p->emulator->region_address),0,(size_t)count);
    return h;
}
static uint64_t win_gdi_default_bitmap(xxemul_windows *p)
{
    size_t i;
    uint64_t h;
    for(i=0;i<WIN_GUI_OBJECTS;i++)if(p->gui_objects[i].active&&p->gui_objects[i].kind==WIN_GUI_BITMAP&&p->gui_objects[i].id==21u)return 0x10000u+i;
    h=win_gdi_bitmap(p,1,1,1u);
    if(h)win_gui_at(p,h)->id=21u;
    return h;
}
static uint64_t win_gdi_default_font(xxemul_windows *p)
{
    size_t i;
    uint64_t h;
    win_gui_object *o;
    static const char name[]="System";
    for(i=0;i<WIN_GUI_OBJECTS;i++)if(p->gui_objects[i].active&&p->gui_objects[i].kind==WIN_GUI_FONT&&p->gui_objects[i].id==13u&&p->gui_objects[i].style==1u)return 0x10000u+i;
    h=win_gui_new(p,WIN_GUI_FONT,0u);
    if(!h){
        p->last_error=8u;
        return 0;
    }
    o=win_gui_at(p,h);
    o->id=13u;
    o->style=1u;
    win_put32(o->logfont,16u);
    o->logfont[23]=1u;
    for(i=0;i<sizeof(name);i++)o->text[i]=(uint8_t)name[i];
    return h;
}
static uint32_t win_gdi_rgb(uint32_t colorref)
{
    return ((colorref&0xffu)<<16)|(colorref&0xff00u)|((colorref>>16)&0xffu);
}
static uint32_t win_gdi_pixel(xxemul_windows *p,win_gui_object *o,int32_t x,int32_t y)
{
    const uint8_t *row=p->emulator->region_data+(size_t)(o->resource-p->emulator->region_address)+(size_t)(o->height-1-y)*(uint32_t)o->increment;
    return o->style==1u?((row[(uint32_t)x/8u]&(0x80u>>((uint32_t)x&7u)))?UINT32_C(0xffffff):0u):win_gdi_u32(row+(size_t)x*4u);
}
static void win_gdi_pixel_store(xxemul_windows *p,win_gui_object *o,int32_t x,int32_t y,uint32_t value)
{
    uint8_t *row=p->emulator->region_data+(size_t)(o->resource-p->emulator->region_address)+(size_t)(o->height-1-y)*(uint32_t)o->increment;
    if(o->style==1u){
        uint8_t bit=(uint8_t)(0x80u>>((uint32_t)x&7u));
        if(value)row[(uint32_t)x/8u]|=bit;
        else row[(uint32_t)x/8u]&=(uint8_t)~bit;
    }
    else win_put32(row+(size_t)x*4u,value);
}
#include "xxemul_windows_stretch_dib.inc"
static int win_gdi_call(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    win_gui_object *o;
    uint8_t width=win_word_size(p->emulator);
    *status=XXEMUL_STATUS_OK;
    if(win_equal(name,"StretchDIBits"))return win_stretch_dib(p,arg,result,status);
    if(win_equal(name,"CreateIcon")){
        int32_t cx=(int32_t)arg[1],cy=(int32_t)arg[2];
        unsigned planes=(uint8_t)arg[3],bpp=(uint8_t)arg[4];
        uint64_t mask,colors,total,h,data;
        uint8_t *copy;
        if(cx<=0||cy<=0||cx>8192||cy>8192||planes!=1u){
            p->last_error=87u;
            return 1;
        }
        if(bpp!=1u&&bpp!=32u){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        mask=((uint64_t)(uint32_t)cx+15u)/16u*2u*(uint32_t)cy;
        colors=((uint64_t)(uint32_t)cx*bpp+15u)/16u*2u*(uint32_t)cy;
        total=mask+colors;
        if(total>16u*1024u*1024u){
            p->last_error=8u;
            return 1;
        }
        copy=(uint8_t*)malloc((size_t)total);
        if(!copy){
            p->last_error=8u;
            return 1;
        }
        if(!win_read(p,arg[5],copy,(size_t)mask)||!win_read(p,arg[6],copy+(size_t)mask,(size_t)colors)){
            free(copy);
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        h=win_gui_new(p,WIN_GUI_ICON,0u);
        if(!h){
            free(copy);
            p->last_error=8u;
            return 1;
        }
        data=win_heap_alloc(p,total);
        if(!data){
            memset(win_gui_at(p,h),0,sizeof(*o));
            free(copy);
            p->last_error=8u;
            return 1;
        }
        win_find_allocation(p,data)->heap_owner=UINT64_MAX;
        o=win_gui_at(p,h);
        o->resource=data;
        o->resource_size=(uint32_t)total;
        o->width=cx;
        o->height=cy;
        o->instance=arg[0];
        o->increment=(int32_t)mask;
        o->maximum=(int32_t)bpp;
        memcpy(p->emulator->region_data+(size_t)(data-p->emulator->region_address),copy,(size_t)total);
        free(copy);
        *result=h;
        return 1;
    }
    if(win_equal(name,"DestroyIcon")){
        win_allocation *a;
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_ICON){
            p->last_error=6u;
            return 1;
        }
        if(o->style==1u){
            p->last_error=87u;
            return 1;
        }
        a=win_find_allocation(p,o->resource);
        if(a)a->active=0;
        memset(o,0,sizeof(*o));
        *result=1u;
        return 1;
    }
    if(win_equal(name,"CreateCompatibleDC")){
        uint64_t h,bm;
        if(arg[0]){
            o=win_gui_at(p,arg[0]);
            if(!o||o->kind!=WIN_GUI_DC){
                p->last_error=6u;
                return 1;
            }
        }
        bm=win_gdi_default_bitmap(p);
        if(!bm)return 1;
        h=win_gui_new(p,WIN_GUI_DC,0u);
        if(!h){
            p->last_error=8u;
            return 1;
        }
        o=win_gui_at(p,h);
        o->owner_id=p->threads[p->thread_current].id;
        o->style=1u;
        o->resource=bm;
        o->icon[0]=0xffffffu;
        o->id=2u;
        *result=h;
        return 1;
    }
    if(win_equal(name,"DeleteDC")){
        win_gui_object *bm;
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_DC||!o->style||o->owner_id!=p->threads[p->thread_current].id){
            p->last_error=6u;
            return 1;
        }
        bm=win_gui_at(p,o->resource);
        if(bm&&bm->kind==WIN_GUI_BITMAP&&!bm->id)bm->parent=0;
        memset(o,0,sizeof(*o));
        *result=1;
        return 1;
    }
    if(win_equal(name,"CreateBitmap")){
        int32_t cx=(int32_t)arg[0],cy=(int32_t)arg[1];
        unsigned planes=(uint32_t)arg[2],bpp=(uint32_t)arg[3];
        uint64_t h,count;
        uint8_t *copy=NULL;
        if(cx<0||cy<0||planes!=1u){
            p->last_error=87u;
            return 1;
        }
        if(!cx||!cy){
            cx=cy=1;
            bpp=1u;
        }
        if(bpp!=1u&&bpp!=32u){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        if(cx>8192||cy>8192||(count=((uint64_t)(uint32_t)cx*bpp+15u)/16u*2u*(uint32_t)cy)>16u*1024u*1024u){
            p->last_error=8u;
            return 1;
        }
        if(arg[4]){
            copy=(uint8_t*)malloc((size_t)count);
            if(!copy){
                p->last_error=8u;
                return 1;
            }
            if(!win_read(p,arg[4],copy,(size_t)count)){
                free(copy);
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
        }
        h=win_gdi_bitmap(p,cx,cy,bpp);
        if(h&&copy){
            o=win_gui_at(p,h);
            memcpy(p->emulator->region_data+(size_t)(o->resource-p->emulator->region_address),copy,(size_t)count);
        }
        free(copy);
        *result=h;
        return 1;
    }
    if(win_equal(name,"CreateCompatibleBitmap")){
        unsigned bpp=32u;
        int32_t cx=(int32_t)arg[1],cy=(int32_t)arg[2];
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_DC){
            p->last_error=6u;
            return 1;
        }
        if(cx<0||cy<0){
            p->last_error=87u;
            return 1;
        }
        if(!cx||!cy){
            cx=cy=1;
            bpp=1u;
        }
        else if(o->style){
            win_gui_object *bm=win_gui_at(p,o->resource);
            if(!bm||bm->kind!=WIN_GUI_BITMAP){
                p->last_error=6u;
                return 1;
            }
            bpp=bm->style;
        }
        *result=win_gdi_bitmap(p,cx,cy,bpp);
        return 1;
    }
    if(win_equal(name,"SelectObject")){
        win_gui_object *obj,*old;
        o=win_gui_at(p,arg[0]);
        obj=win_gui_at(p,arg[1]);
        if(!o||o->kind!=WIN_GUI_DC||!obj){
            p->last_error=6u;
            return 1;
        }
        if(obj->kind==WIN_GUI_BITMAP){
            if(!o->style||(obj->parent&&obj->parent!=arg[0]&&!obj->id)){
                p->last_error=87u;
                return 1;
            }
            old=win_gui_at(p,o->resource);
            *result=o->resource;
            if(old&&!old->id)old->parent=0;
            o->resource=arg[1];
            if(!obj->id)obj->parent=arg[0];
            return 1;
        }
        if(obj->kind==WIN_GUI_FONT){
            if(!o->font){
                o->font=win_gdi_default_font(p);
                if(!o->font)return 1;
            }
            *result=o->font;
            o->font=arg[1];
            return 1;
        }
        *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        return 1;
    }
    if(win_equal(name,"SetBkColor")||win_equal(name,"SetTextColor")||win_equal(name,"SetBkMode")){
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_DC){
            p->last_error=6u;
            *result=UINT32_MAX;
            return 1;
        }
        if(win_equal(name,"SetBkMode")){
            if((uint32_t)arg[1]!=1u&&(uint32_t)arg[1]!=2u){
                p->last_error=87u;
                return 1;
            }
            *result=o->id?o->id:2u;
            o->id=(uint32_t)arg[1];
        }
        else{
            unsigned field=win_equal(name,"SetBkColor")?0u:1u;
            *result=o->icon[field];
            o->icon[field]=(uint32_t)arg[1]&0xffffffu;
        }
        return 1;
    }
    if(win_equal(name,"GetBitmapBits")){
        uint32_t amount=(uint32_t)arg[1];
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_BITMAP){
            p->last_error=6u;
            return 1;
        }
        if((int32_t)amount<0){
            p->last_error=87u;
            return 1;
        }
        if(amount>o->resource_size)amount=o->resource_size;
        if(!amount)return 1;
        uint8_t *copy=(uint8_t*)malloc(amount);
        if(!copy){
            p->last_error=8u;
            return 1;
        }
        memcpy(copy,p->emulator->region_data+(size_t)(o->resource-p->emulator->region_address),amount);
        int written=win_write(p,arg[2],copy,amount);
        free(copy);
        if(!written){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        *result=amount;
        return 1;
    }
    if(win_equal(name,"BitBlt")||win_equal(name,"StretchBlt")){
        win_gui_object *source_dc,*src,*dst;
        uint32_t rop=(uint32_t)arg[win_equal(name,"StretchBlt")?10u:8u],*copy;
        int32_t x=(int32_t)arg[1],y=(int32_t)arg[2],cx=(int32_t)arg[3],cy=(int32_t)arg[4],sx=(int32_t)arg[6],sy=(int32_t)arg[7];
        if(win_equal(name,"StretchBlt")&&((int32_t)arg[8]!=cx||(int32_t)arg[9]!=cy)){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        o=win_gui_at(p,arg[0]);
        source_dc=win_gui_at(p,arg[5]);
        if(!o||o->kind!=WIN_GUI_DC||!source_dc||source_dc->kind!=WIN_GUI_DC){
            p->last_error=6u;
            return 1;
        }
        if(rop!=0xcc0020u&&rop!=0x8800c6u&&rop!=0xee0086u&&rop!=0x660046u&&rop!=0x330008u&&rop!=0x1100a6u&&rop!=0x42u&&rop!=0xff0062u){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        dst=win_gdi_surface(p,o,status);
        if(!dst)return 1;
        src=win_gdi_surface(p,source_dc,status);
        if(!src)return 1;
        if(!dst||!src||dst->kind!=WIN_GUI_BITMAP||src->kind!=WIN_GUI_BITMAP){
            p->last_error=6u;
            return 1;
        }
        if(cx<=0||cy<=0||x<0||y<0||sx<0||sy<0||x>dst->width||cx>dst->width-x||y>dst->height||cy>dst->height-y||sx>src->width||cx>src->width-sx||sy>src->height||cy>src->height-sy){
            p->last_error=87u;
            return 1;
        }
        if((uint64_t)(uint32_t)cx*(uint32_t)cy>4u*1024u*1024u){
            p->last_error=8u;
            return 1;
        }
        copy=(uint32_t*)malloc((size_t)cx*(uint32_t)cy*sizeof(*copy));
        if(!copy){
            p->last_error=8u;
            return 1;
        }
        for(int32_t row=0;row<cy;row++)for(int32_t col=0;col<cx;col++){
            uint32_t pixel=win_gdi_pixel(p,src,sx+col,sy+row);
            if(src->style==1u&&dst->style==32u)pixel=win_gdi_rgb((uint32_t)(pixel?o->icon[0]:o->icon[1]));
            else if(src->style==32u&&dst->style==1u)pixel=(pixel&0xffffffu)==win_gdi_rgb((uint32_t)source_dc->icon[0])?0xffffffu:0u;
            copy[(size_t)row*(uint32_t)cx+col]=pixel;
        }
        for(int32_t row=0;row<cy;row++)for(int32_t col=0;col<cx;col++){
            uint32_t a=copy[(size_t)row*(uint32_t)cx+col],b=win_gdi_pixel(p,dst,x+col,y+row),v;
            switch(rop){
                case 0xcc0020u:v=a;
                break;
                case 0x8800c6u:v=a&b;
                break;
                case 0xee0086u:v=a|b;
                break;
                case 0x660046u:v=a^b;
                break;
                case 0x330008u:v=~a;
                break;
                case 0x1100a6u:v=~(a|b);
                break;
                case 0x42u:v=0;
                break;
                default:v=UINT32_MAX;
                break;
            }
            if(win_gdi_clip(p,o,x+col,y+row))win_gdi_pixel_store(p,dst,x+col,y+row,dst->style==1u?(v&0xffffffu)!=0:v);
        }
        free(copy);
        *result=1u;
        return 1;
    }
    if(win_equal(name,"CreateDIBitmap")){
        uint8_t header[124],info[124],*pixels=NULL;
        uint32_t size,format,colors,source_stride,palette[2]={
            0,0xffffffu
        };
        int32_t cx,cy;
        uint64_t count,h,data;
        win_allocation *allocation;
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_DC||o->owner_id!=p->threads[p->thread_current].id){
            p->last_error=6u;
            return 1;
        }
        if(!win_read(p,arg[1],header,40u)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        size=win_gdi_u32(header);
        cx=(int32_t)win_gdi_u32(header+4);
        cy=(int32_t)win_gdi_u32(header+8);
        format=win_gdi_u32(header+16);
        colors=win_gdi_u32(header+12);
        if((size!=40u&&size!=108u&&size!=124u)||cx<=0||!cy||cy==INT32_MIN||(colors&0xffffu)!=1u||((uint32_t)arg[2]&~UINT32_C(4))||(uint32_t)arg[5]>1u){
            p->last_error=87u;
            return 1;
        }
        if(size>40u&&!win_read(p,arg[1],header,size)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        if(cx>8192||cy>8192||cy< -8192){
            p->last_error=8u;
            return 1;
        }
        if(((colors>>16)!=32u&&(colors>>16)!=1u)||format||(uint32_t)arg[5]){
            *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        count=(uint64_t)(uint32_t)cx*4u*(uint32_t)(cy<0?-cy:cy);
        if(count>16u*1024u*1024u){
            p->last_error=8u;
            return 1;
        }
        source_stride=(uint32_t)(((uint64_t)(uint32_t)cx*(colors>>16)+31u)/32u*4u);
        if(arg[2]&4u){
            if(!win_read(p,arg[4],info,size)){
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
            if(win_gdi_u32(info)!=size||win_gdi_u32(info+4)!=(uint32_t)cx||win_gdi_u32(info+8)!=(uint32_t)cy||win_gdi_u32(info+12)!=colors||win_gdi_u32(info+16)!=format){
                p->last_error=87u;
                return 1;
            }
            if((colors>>16)==1u){
                uint8_t table[8];
                if(!win_read(p,arg[4]+size,table,8u)){
                    *status=XXEMUL_STATUS_ADDRESS_FAULT;
                    return 1;
                }
                palette[0]=win_gdi_u32(table)&0xffffffu;
                palette[1]=win_gdi_u32(table+4)&0xffffffu;
            }
            pixels=(uint8_t*)malloc((size_t)source_stride*(uint32_t)(cy<0?-cy:cy));
            if(!pixels){
                p->last_error=8u;
                return 1;
            }
            if(!win_read(p,arg[3],pixels,(size_t)source_stride*(uint32_t)(cy<0?-cy:cy))){
                free(pixels);
                *status=XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
        }
        h=win_gui_new(p,WIN_GUI_BITMAP,0u);
        if(!h){
            free(pixels);
            p->last_error=8u;
            return 1;
        }
        data=win_heap_alloc(p,count);
        if(!data){
            free(pixels);
            memset(win_gui_at(p,h),0,sizeof(*o));
            p->last_error=8u;
            return 1;
        }
        allocation=win_find_allocation(p,data);
        allocation->heap_owner=UINT64_MAX;
        o=win_gui_at(p,h);
        o->resource=data;
        o->resource_size=(uint32_t)count;
        o->width=cx;
        o->height=cy<0?-cy:cy;
        o->style=32u;
        o->increment=cx*4;
        if(pixels){
            /* Canonical private rows are bottom-up like a positive-height DIB. */
            size_t row=(size_t)cx*4u;
            for(int32_t y=0;y<o->height;y++){
                const uint8_t *src=pixels+(size_t)(cy<0?o->height-y-1:y)*source_stride;
                uint8_t *dst=p->emulator->region_data+(size_t)(data-p->emulator->region_address)+(size_t)y*row;
                if((colors>>16)==32u)memcpy(dst,src,row);
                else for(int32_t x=0;x<cx;x++)win_put32(dst+(size_t)x*4u,palette[(src[(uint32_t)x/8u]>>(7u-((uint32_t)x&7u)))&1u]);
            }
            free(pixels);
        }
        *result=h;
        return 1;
    }
    if(win_equal(name,"GetObjectA")||win_equal(name,"GetObjectW")){
        uint8_t bitmap[32]={
            0
        };
        unsigned amount=width==8u?32u:24u;
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_BITMAP)return 0;
        if(!arg[2]){
            *result=amount;
            return 1;
        }
        if((int32_t)arg[1]<(int32_t)amount){
            p->last_error=87u;
            return 1;
        }
        win_put32(bitmap+4,(uint32_t)o->width);
        win_put32(bitmap+8,(uint32_t)o->height);
        win_put32(bitmap+12,(uint32_t)o->increment);
        bitmap[16]=1u;
        bitmap[18]=(uint8_t)o->style;
        if(!win_write(p,arg[2],bitmap,amount)){
            *status=XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
        *result=amount;
        return 1;
    }
    if(win_equal(name,"DeleteObject")){
        o=win_gui_at(p,arg[0]);
        if(o&&o->kind==WIN_GUI_FONT){
            if(o->id==13u&&o->style==1u){
                *result=1;
                return 1;
            }
            for(size_t i=0;i<WIN_GUI_OBJECTS;i++)if(p->gui_objects[i].active&&p->gui_objects[i].kind==WIN_GUI_DC&&p->gui_objects[i].font==arg[0]){
                p->last_error=170u;
                return 1;
            }
        }
        win_allocation *a;
        o=win_gui_at(p,arg[0]);
        if(!o||o->kind!=WIN_GUI_BITMAP)return 0;
        if(o->id){
            *result=1;
            return 1;
        }
        if(o->parent){
            p->last_error=170u;
            return 1;
        }
        a=win_find_allocation(p,o->resource);
        if(a)a->active=0;
        memset(o,0,sizeof(*o));
        *result=1u;
        return 1;
    }
    return 0;
}
