/* Process-private GDI regions represented as canonical nonoverlapping y bands.
 * Boolean operations build a separate bounded candidate before committing, so
 * either source may alias the destination and failed operations preserve it. */
typedef struct win_region_interval { int32_t left, right; } win_region_interval;
static win_gui_object *win_region_at(xxemul_windows *p,uint64_t h)
{
    win_gui_object *o=win_gui_at(p,h);
    return o&&o->kind==WIN_GUI_REGION&&!o->parent?o:NULL;
}
static uint32_t win_region_type(const win_gui_object *o)
{return !o->region_count?1u:o->region_count==1u?2u:3u;}
static win_region_rect win_region_bounds(const win_gui_object *o)
{
    win_region_rect box={0,0,0,0};
    if(o->region_count){box=o->region_rects[0];for(uint32_t i=1;i<o->region_count;i++){
        const win_region_rect *r=&o->region_rects[i];
        if(r->left<box.left)box.left=r->left;if(r->top<box.top)box.top=r->top;
        if(r->right>box.right)box.right=r->right;if(r->bottom>box.bottom)box.bottom=r->bottom;
    }}
    return box;
}
static int win_region_i32_compare(const void *a,const void *b)
{int32_t x=*(const int32_t *)a,y=*(const int32_t *)b;return x<y?-1:x>y;}
static int win_region_truth(unsigned mode,int a,int b)
{return mode==1u?a&&b:mode==2u?a||b:mode==3u?a!=b:mode==4u?a&&!b:a;}
static const win_region_rect *win_region_band(const win_gui_object *o,int32_t y,uint32_t *cursor,uint32_t *count)
{
    *count=0;
    if(!o)return NULL;
    while(*cursor<o->region_count&&o->region_rects[*cursor].bottom<=y)++*cursor;
    if(*cursor==o->region_count||o->region_rects[*cursor].top>y)return NULL;
    for(uint32_t i=*cursor;i<o->region_count&&o->region_rects[i].top==o->region_rects[*cursor].top;i++)++*count;
    return o->region_rects+*cursor;
}
/* Merge ordered interval endpoints. Equal endpoints are consumed together,
 * including touching source regions, before computing the next output state. */
static uint32_t win_region_intervals(const win_region_rect *a,uint32_t na,const win_region_rect *b,uint32_t nb,
                                    unsigned mode,win_region_interval *out)
{
    uint32_t ia=0,ib=0,n=0;int in_a=0,in_b=0,on=0;int32_t start=0;
    while(ia<na||ib<nb||in_a||in_b){
        int have_a=ia<na,have_b=ib<nb;
        int32_t xa=have_a?(in_a?a[ia].right:a[ia].left):INT32_MAX;
        int32_t xb=have_b?(in_b?b[ib].right:b[ib].left):INT32_MAX;
        int32_t x=xa<xb?xa:xb;
        if(have_a&&xa==x){if(in_a){in_a=0;++ia;}else in_a=1;}
        if(have_b&&xb==x){if(in_b){in_b=0;++ib;}else in_b=1;}
        int next=win_region_truth(mode,in_a,in_b);
        if(next&&!on)start=x;
        if(!next&&on){out[n].left=start;out[n].right=x;++n;}
        on=next;
    }
    return n;
}
static int win_region_combine(const win_gui_object *a,const win_gui_object *b,unsigned mode,
                              win_region_rect **out,uint32_t *out_count)
{
    uint32_t total=a->region_count+(b?b->region_count:0u),ny=0,count=0,ca=0,cb=0;
    uint32_t previous_start=0,previous_count=0;
    win_region_rect *rects=NULL;
    win_region_interval *intervals=NULL;
    int32_t *ys=NULL;
    *out=NULL;*out_count=0;
    if(!total)return 1;
    ys=(int32_t *)malloc((size_t)total*2u*sizeof(*ys));
    intervals=(win_region_interval *)malloc((size_t)total*sizeof(*intervals));
    rects=(win_region_rect *)malloc(WIN_REGION_MAX_RECTS*sizeof(*rects));
    if(!ys||!intervals||!rects)goto failed;
    for(uint32_t i=0;i<a->region_count;i++){ys[ny++]=a->region_rects[i].top;ys[ny++]=a->region_rects[i].bottom;}
    if(b)for(uint32_t i=0;i<b->region_count;i++){ys[ny++]=b->region_rects[i].top;ys[ny++]=b->region_rects[i].bottom;}
    qsort(ys,ny,sizeof(*ys),win_region_i32_compare);
    {uint32_t unique=0;for(uint32_t i=0;i<ny;i++)if(!unique||ys[i]!=ys[unique-1u])ys[unique++]=ys[i];ny=unique;}
    for(uint32_t y=0;y+1u<ny;y++){
        uint32_t na,nb,n;const win_region_rect *ba=win_region_band(a,ys[y],&ca,&na),*bb=win_region_band(b,ys[y],&cb,&nb);
        n=win_region_intervals(ba,na,bb,nb,mode,intervals);
        int merge=n&&n==previous_count&&rects[previous_start].bottom==ys[y];
        if(merge)for(uint32_t i=0;i<n;i++)if(rects[previous_start+i].left!=intervals[i].left||rects[previous_start+i].right!=intervals[i].right){merge=0;break;}
        if(merge){for(uint32_t i=0;i<n;i++)rects[previous_start+i].bottom=ys[y+1u];continue;}
        if(n>WIN_REGION_MAX_RECTS-count)goto failed;
        previous_start=count;previous_count=n;
        for(uint32_t i=0;i<n;i++)rects[count++]=(win_region_rect){intervals[i].left,ys[y],intervals[i].right,ys[y+1u]};
    }
    free(ys);free(intervals);
    if(!count){free(rects);rects=NULL;}
    *out=rects;*out_count=count;return 1;
failed:
    free(ys);free(intervals);free(rects);return 0;
}
static void win_region_put_rect(uint8_t *bytes,const win_region_rect *r)
{win_put32(bytes,(uint32_t)r->left);win_put32(bytes+4u,(uint32_t)r->top);win_put32(bytes+8u,(uint32_t)r->right);win_put32(bytes+12u,(uint32_t)r->bottom);}
static int win_region_call(xxemul_windows *p,const char *name,const uint64_t *arg,uint64_t *result,xxemul_status *status)
{
    win_gui_object *o;
    *status=XXEMUL_STATUS_OK;
    if(win_equal(name,"SetWindowRgn")){
        win_gui_object *window=win_window_at(p,arg[0]),*region=NULL,*old;
        win_window_frame *frame;uint8_t pos[40]={0};uint8_t width=win_word_size(p->emulator);unsigned off=width*2u;
        if(!window||window->owner_id!=p->threads[p->thread_current].id){p->last_error=1400u;return 1;}
        if(arg[1]&&!(region=win_region_at(p,arg[1]))){p->last_error=6u;return 1;}
        frame=win_window_request(p,arg[0],7u);if(!frame)return 1;
        frame->data=win_heap_alloc(p,width==8u?40u:28u);
        if(!frame->data){memset(frame,0,sizeof(*frame));p->window_pending=0;p->last_error=8u;return 1;}
        win_find_allocation(p,frame->data)->heap_owner=UINT64_MAX;
        if(width==8u)win_put64(pos,arg[0]);else win_put32(pos,(uint32_t)arg[0]);
        win_put32(pos+off,(uint32_t)window->x);win_put32(pos+off+4u,(uint32_t)window->y);
        win_put32(pos+off+8u,(uint32_t)window->width);win_put32(pos+off+12u,(uint32_t)window->height);
        /* FRAMECHANGED, NOSIZE, NOMOVE, NOZORDER, NOACTIVATE; NOREDRAW
         * follows the effective BOOL. Presentation remains headless. */
        win_put32(pos+off+16u,0x37u|((uint32_t)arg[2]?0u:8u));
        if(!win_write(p,frame->data,pos,width==8u?40u:28u)){
            win_find_allocation(p,frame->data)->active=0;memset(frame,0,sizeof(*frame));p->window_pending=0;
            *status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;
        }
        old=win_gui_at(p,window->window_region);
        if(old&&old->kind==WIN_GUI_REGION){free(old->region_rects);memset(old,0,sizeof(*old));}
        window->window_region=arg[1];if(region)region->parent=arg[0];*result=1u;return 1;
    }
    if(win_equal(name,"GetWindowRgn")){
        win_gui_object *window=win_window_at(p,arg[0]),*region;win_region_rect *copy=NULL;
        if(!window){p->last_error=1400u;return 1;}o=win_region_at(p,arg[1]);if(!o){p->last_error=6u;return 1;}
        region=win_gui_at(p,window->window_region);if(!region)return 1;
        if(region->region_count){copy=(win_region_rect*)malloc(region->region_count*sizeof(*copy));if(!copy){p->last_error=8u;return 1;}memcpy(copy,region->region_rects,region->region_count*sizeof(*copy));}
        free(o->region_rects);o->region_rects=copy;o->region_count=region->region_count;*result=win_region_type(o);return 1;
    }
    if(win_equal(name,"CreateRectRgn")){
        int32_t v[4];uint64_t handle;win_region_rect *r=NULL;
        for(unsigned i=0;i<4u;i++){v[i]=(int32_t)arg[i];if(v[i]<-INT32_C(67108864)||v[i]>INT32_C(67108863)){p->last_error=87u;return 1;}}
        if(v[0]>v[2]){int32_t t=v[0];v[0]=v[2];v[2]=t;}if(v[1]>v[3]){int32_t t=v[1];v[1]=v[3];v[3]=t;}
        if(v[0]!=v[2]&&v[1]!=v[3]){r=(win_region_rect *)malloc(sizeof(*r));if(!r){p->last_error=8u;return 1;}*r=(win_region_rect){v[0],v[1],v[2],v[3]};}
        handle=win_gui_new(p,WIN_GUI_REGION,0u);if(!handle){free(r);p->last_error=8u;return 1;}
        o=win_region_at(p,handle);o->region_rects=r;o->region_count=r?1u:0u;*result=handle;return 1;
    }
    if(win_equal(name,"CombineRgn")){
        unsigned mode=(uint32_t)arg[3];win_gui_object *a,*b;win_region_rect *rects;uint32_t count;
        if(mode<1u||mode>5u){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
        o=win_region_at(p,arg[0]);a=win_region_at(p,arg[1]);b=mode==5u?NULL:win_region_at(p,arg[2]);
        if(!o||!a||(mode!=5u&&!b)){p->last_error=6u;return 1;}
        if(!win_region_combine(a,b,mode,&rects,&count)){p->last_error=8u;return 1;}
        free(o->region_rects);o->region_rects=rects;o->region_count=count;*result=win_region_type(o);return 1;
    }
    if(win_equal(name,"DeleteObject")){
        o=win_gui_at(p,arg[0]);if(!o||o->kind!=WIN_GUI_REGION)return 0;
        if(o->parent){p->last_error=6u;return 1;}
        free(o->region_rects);memset(o,0,sizeof(*o));*result=1u;return 1;
    }
    if(win_equal(name,"GetRgnBox")||win_equal(name,"GetRegionData")||win_equal(name,"PtInRegion")){
        win_region_rect box;o=win_region_at(p,arg[0]);if(!o){p->last_error=6u;return 1;}
        if(win_equal(name,"PtInRegion")){
            int32_t x=(int32_t)arg[1],y=(int32_t)arg[2];
            for(uint32_t i=0;i<o->region_count;i++){const win_region_rect *r=&o->region_rects[i];if(x>=r->left&&x<r->right&&y>=r->top&&y<r->bottom){*result=1u;break;}}
            return 1;
        }
        box=win_region_bounds(o);
        if(win_equal(name,"GetRgnBox")){
            uint8_t bytes[16];win_region_put_rect(bytes,&box);if(!win_write(p,arg[1],bytes,sizeof(bytes))){*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
            *result=win_region_type(o);return 1;
        }else{
            uint32_t bytes=32u+o->region_count*16u;uint8_t *data;
            if(!arg[2]){*result=bytes;return 1;}
            if((uint32_t)arg[1]<bytes){p->last_error=87u;return 1;}
            data=(uint8_t *)calloc(1,bytes);if(!data){p->last_error=8u;return 1;}
            win_put32(data,32u);win_put32(data+4u,1u);win_put32(data+8u,o->region_count);win_put32(data+12u,o->region_count*16u);win_region_put_rect(data+16u,&box);
            for(uint32_t i=0;i<o->region_count;i++)win_region_put_rect(data+32u+i*16u,&o->region_rects[i]);
            if(!win_write(p,arg[2],data,bytes)){free(data);*status=XXEMUL_STATUS_ADDRESS_FAULT;return 1;}
            free(data);*result=bytes;return 1;
        }
    }
    return 0;
}
