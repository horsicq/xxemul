/* Bounded 8-bit RGB DIB conversion and integer enlargement. Window DC pixels
 * belong to an engine-owned backing bitmap, not a host desktop or renderer. */
static win_gui_object *win_gdi_surface(xxemul_windows *p,win_gui_object *dc,xxemul_status *status)
{
    win_gui_object *window,*bitmap,*old;
    uint64_t h;
    if(dc->owner_id!=p->threads[p->thread_current].id){p->last_error=6u;return NULL;}
    if(dc->style){bitmap=win_gui_at(p,dc->resource);return bitmap&&bitmap->kind==WIN_GUI_BITMAP?bitmap:NULL;}
    window=win_window_at(p,dc->parent);
    if(!window){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return NULL;}
    old=win_gui_at(p,window->canvas);
    if(old&&old->kind==WIN_GUI_BITMAP&&old->width==window->width&&old->height==window->height)return old;
    if(window->width<=0||window->height<=0){p->last_error=87u;return NULL;}
    h=win_gdi_bitmap(p,window->width,window->height,32u);if(!h)return NULL;
    bitmap=win_gui_at(p,h);bitmap->parent=win_window_handle(p,window);
    if(old&&old->kind==WIN_GUI_BITMAP){
        int32_t cx=old->width<bitmap->width?old->width:bitmap->width,cy=old->height<bitmap->height?old->height:bitmap->height;
        for(int32_t y=0;y<cy;y++)for(int32_t x=0;x<cx;x++)win_gdi_pixel_store(p,bitmap,x,y,win_gdi_pixel(p,old,x,y));
        win_allocation *allocation=win_find_allocation(p,old->resource);if(allocation)allocation->active=0;
        memset(old,0,sizeof(*old));
    }
    window->canvas=h;return bitmap;
}
static int win_gdi_clip(xxemul_windows *p,const win_gui_object *dc,int32_t x,int32_t y)
{
    const win_gui_object *window,*region;
    if(dc->style)return 1;
    window=win_window_at(p,dc->parent);if(!window)return 0;
    region=win_gui_at(p,window->window_region);if(!region)return 1;
    for(uint32_t i=0;i<region->region_count;i++){
        const win_region_rect *r=&region->region_rects[i];
        if(x>=r->left&&x<r->right&&y>=r->top&&y<r->bottom)return 1;
    }
    return 0;
}
static int win_stretch_dib(xxemul_windows *p,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    win_gui_object *dc=win_gui_at(p,arg[0]),*dst;
    uint8_t header[40],table[1024],*bits=NULL;
    uint32_t palette[256],colors,stride;
    int32_t width,height,rows,x=(int32_t)arg[1],y=(int32_t)arg[2],cx=(int32_t)arg[3],cy=(int32_t)arg[4];
    uint64_t bytes;
    if(!dc||dc->kind!=WIN_GUI_DC||dc->owner_id!=p->threads[p->thread_current].id){p->last_error=6u;return 1;}
    if((uint32_t)arg[11]||(uint32_t)arg[12]!=0xcc0020u){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
    if(!win_read(p,arg[10],header,4u)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
    uint32_t header_size=win_gdi_u32(header);
    /* Recognized unimplemented CORE/V4/V5 headers decline after biSize alone;
     * no 40-byte probe is valid for a page-ending 12-byte CORE header. */
    if(header_size==12u||header_size==108u||header_size==124u){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
    if(header_size!=40u){p->last_error=87u;return 1;}
    if(!win_read(p,arg[10],header,sizeof(header))){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
    width=(int32_t)win_gdi_u32(header+4u);height=(int32_t)win_gdi_u32(header+8u);
    if(win_gdi_u32(header)!=40u||width<=0||!height||height==INT32_MIN||(win_gdi_u32(header+12u)&0xffffu)!=1u){p->last_error=87u;return 1;}
    if((win_gdi_u32(header+12u)>>16)!=8u||win_gdi_u32(header+16u)){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
    rows=height<0?-height:height;
    if(width>8192||rows>8192||cx>8192||cy>8192){p->last_error=8u;return 1;}
    if(!cx||!cy)return 1;
    if(cx<0||cy<0||(int32_t)arg[5]||(int32_t)arg[6]||(int32_t)arg[7]!=width||(int32_t)arg[8]!=rows||cx<width||cy<rows||cx%width||cy%rows){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
    if((uint64_t)(uint32_t)cx*(uint32_t)cy>4u*1024u*1024u){p->last_error=8u;return 1;}
    colors=win_gdi_u32(header+32u);if(!colors)colors=256u;if(colors>256u){p->last_error=87u;return 1;}
    if(arg[10]>UINT64_MAX-40u||!win_read(p,arg[10]+40u,table,colors*4u)){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
    for(uint32_t i=0;i<colors;i++)palette[i]=win_gdi_u32(table+i*4u)&0xffffffu;
    stride=((uint32_t)width+3u)&~3u;bytes=(uint64_t)stride*(uint32_t)rows;
    if(bytes>16u*1024u*1024u){p->last_error=8u;return 1;}
    bits=(uint8_t*)malloc((size_t)bytes);if(!bits){p->last_error=8u;return 1;}
    if(!win_read(p,arg[9],bits,(size_t)bytes)){free(bits);*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
    for(int32_t row=0;row<rows;row++)for(int32_t col=0;col<width;col++)if(bits[(size_t)row*stride+col]>=colors){free(bits);p->last_error=87u;return 1;}
    /* Every fallible source check precedes even the allocation of a canvas. */
    dst=win_gdi_surface(p,dc,status);if(!dst){free(bits);return 1;}
    if(dst->style!=32u){free(bits);*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
    int64_t right=(int64_t)x+cx,bottom=(int64_t)y+cy;
    int32_t left=x<0?0:x,top=y<0?0:y;
    int32_t end_x=right>dst->width?dst->width:(int32_t)right,end_y=bottom>dst->height?dst->height:(int32_t)bottom;
    for(int32_t dy=top;dy<end_y;dy++)for(int32_t dx=left;dx<end_x;dx++){
        if(!win_gdi_clip(p,dc,dx,dy))continue;
        uint32_t sx=(uint32_t)(((int64_t)dx-x)/(cx/width)),sy=(uint32_t)(((int64_t)dy-y)/(cy/rows));
        uint32_t source_row=height<0?sy:(uint32_t)rows-1u-sy;
        win_gdi_pixel_store(p,dst,dx,dy,palette[bits[(size_t)source_row*stride+sx]]);
    }
    /* The bounded full-source SRCCOPY compatibility profile returns source
     * height even when destination/region clipping suppresses every pixel. */
    free(bits);*result=(uint32_t)rows;return 1;
}
