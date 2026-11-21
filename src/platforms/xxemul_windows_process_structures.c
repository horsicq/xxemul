#include "xxemul_windows_process_structures.h"
#include <string.h>

#define MODEL_HEAP_SIGNATURE UINT32_C(0x58485031)
#define NT_HEAP_SEGMENT_SIGNATURE UINT32_C(0xffeeffee)
#define MODEL_HEAP_BYTES 0x180u
#define MODEL_HEAP_META 0x100u

static const xxemul_windows_process_layout layout32 = {
    4u,0x500u,0x2000u,0x300u,
    0x18u,4u,8u,0x20u,0x2cu,0x30u,
    0x34u,0xbf4u,0xe10u,0xf94u,0xe0cu,
    8u,0xcu,0x10u,0x18u,0x1cu,0xa0u,
    0x40u,0x44u,0x150u,0x154u,
    0x88u,0x8cu,0x90u,0x68u,
    0xa4u,0xa8u,0xacu,0xb0u,0x1d4u,
    0x40u,0x44u
};
static const xxemul_windows_process_layout layout64 = {
    8u,0x800u,0x2000u,0x440u,
    0x30u,8u,0x10u,0x40u,0x58u,0x60u,
    0x68u,0x1250u,0x1480u,0x1780u,0x1478u,
    0x10u,0x18u,0x20u,0x30u,0x38u,0x110u,
    0x78u,0x80u,0x238u,0x240u,
    0xe8u,0xecu,0xf0u,0xbcu,
    0x118u,0x11cu,0x120u,0x124u,0x2c0u,
    0x70u,0x74u
};

const xxemul_windows_process_layout *xxemul_windows_process_get_layout(int is64)
{ return is64 ? &layout64 : &layout32; }

static int address_valid(uint64_t address, size_t size, unsigned width)
{
    return address && size && address <= UINT64_MAX - (size - 1u) &&
           (width == 8u || (address <= UINT32_MAX && size - 1u <= UINT32_MAX - address));
}

static int load(const xxemul_windows_process_memory *m, uint64_t address,
                void *data, size_t size, unsigned width)
{ return m && m->read && m->write && address_valid(address,size,width) && m->read(m->context,address,data,size); }

static int store(const xxemul_windows_process_memory *m, uint64_t address,
                 const void *data, size_t size, unsigned width)
{ return address_valid(address,size,width) && m->write(m->context,address,data,size); }

static void put(uint8_t *data, unsigned size, uint64_t value)
{ unsigned i; for(i=0u;i<size;++i)data[i]=(uint8_t)(value>>(i*8u)); }
static uint64_t get(const uint8_t *data, unsigned size)
{ uint64_t value=0;unsigned i;for(i=0u;i<size;++i)value|=(uint64_t)data[i]<<(i*8u);return value; }
static int pointer_valid(uint64_t value,unsigned width)
{ return width==8u || value<=UINT32_MAX; }

static int unicode_valid(const xxemul_windows_unicode_value *s,unsigned width)
{
    return !(s->length&1u)&&!(s->maximum_length&1u)&&s->length<=s->maximum_length&&
        ((!s->length&&!s->maximum_length&&!s->address)||
            ((unsigned)s->length+2u<=s->maximum_length&&address_valid(s->address,s->maximum_length,width)));
}
static int probe(const xxemul_windows_process_memory*m,uint64_t address,size_t size,unsigned width)
{
    uint8_t bytes[256];
    while(size){size_t chunk=size<sizeof(bytes)?size:sizeof(bytes);
        if(!load(m,address,bytes,chunk,width))return 0;
        address+=chunk;size-=chunk;}
    return 1;
}
static int unicode_probe(const xxemul_windows_process_memory*m,const xxemul_windows_unicode_value*s,unsigned width)
{
    uint8_t end[2];
    return (!s->address&&!s->maximum_length)||
        (probe(m,s->address,s->maximum_length,width)&&load(m,s->address+s->length,end,2u,width)&&!end[0]&&!end[1]);
}
static void unicode_put(uint8_t *buffer,const xxemul_windows_unicode_value *s,unsigned width)
{
    memset(buffer,0,width==8u?16u:8u);put(buffer,2u,s->length);put(buffer+2u,2u,s->maximum_length);
    put(buffer+(width==8u?8u:4u),width,s->address);
}

static xxemul_status process_valid(const xxemul_windows_process_memory *m,
                                   const xxemul_windows_process_description *d)
{
    const xxemul_windows_process_layout *l;
    if(!m||!m->read||!m->write||!d)return XXEMUL_STATUS_INVALID_ARGUMENT;
    l=xxemul_windows_process_get_layout(d->is64);
    if(!address_valid(d->peb,l->peb_size,l->pointer_size)||
        !address_valid(d->parameters,l->parameters_size,l->pointer_size)||
        !address_valid(d->heap,MODEL_HEAP_BYTES,l->pointer_size)||
        !address_valid(d->loader,d->is64?0x58u:0x30u,l->pointer_size)||
        !pointer_valid(d->image_base,l->pointer_size)||!d->image_base||
        !pointer_valid(d->heap_start,l->pointer_size)||!pointer_valid(d->heap_limit,l->pointer_size)||d->heap_start>=d->heap_limit||
        d->heap_count==0u||d->heap_count>d->heap_capacity||d->heap_capacity>64u||
        !address_valid(d->heap_list,d->heap_capacity*l->pointer_size,l->pointer_size)||
        d->tls_capacity<64u||d->tls_capacity>1088u||
        !address_valid(d->tls_bitmap,l->pointer_size==8u?16u:8u,l->pointer_size)||
        !address_valid(d->tls_expansion_bitmap,l->pointer_size==8u?16u:8u,l->pointer_size)||
        !unicode_valid(&d->image_path,l->pointer_size)||!unicode_valid(&d->command_line,l->pointer_size)||
        !unicode_valid(&d->current_directory,l->pointer_size)||!unicode_valid(&d->dll_path,l->pointer_size)||
        d->environment_bytes<4u||d->environment_bytes>0x1000000u||
        !address_valid(d->environment,(size_t)d->environment_bytes,l->pointer_size)||(d->environment_bytes&1u)||
        d->heap_limit-d->heap_start>UINT64_C(0xffffffff)*0x1000u||
        (d->heap_count>1u&&!d->heaps)||!d->processor_count||!d->affinity_mask||
        !pointer_valid(d->affinity_mask,l->pointer_size))return XXEMUL_STATUS_INVALID_ARGUMENT;
    return XXEMUL_STATUS_OK;
}
static int parameter_payloads(const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d,unsigned width)
{
    uint8_t end[4];
    return unicode_probe(m,&d->image_path,width)&&unicode_probe(m,&d->command_line,width)&&
        unicode_probe(m,&d->current_directory,width)&&unicode_probe(m,&d->dll_path,width)&&
        probe(m,d->environment,(size_t)d->environment_bytes,width)&&
        load(m,d->environment+d->environment_bytes-4u,end,4u,width)&&!get(end,4u);
}

xxemul_status xxemul_windows_process_update_parameters(
 const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d)
{
    uint8_t bytes[0x440];unsigned width;xxemul_status status=process_valid(m,d);
    const xxemul_windows_process_layout*l;
    if(status!=XXEMUL_STATUS_OK)return status;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;
    if(!parameter_payloads(m,d,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(!load(m,d->parameters,bytes,l->parameters_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    put(bytes,4u,l->parameters_size);put(bytes+4u,4u,l->parameters_size);put(bytes+8u,4u,1u);
    put(bytes+0x10u,width,d->console_handle);
    put(bytes+(d->is64?0x20u:0x18u),width,d->standard_input);
    put(bytes+(d->is64?0x28u:0x1cu),width,d->standard_output);
    put(bytes+(d->is64?0x30u:0x20u),width,d->standard_error);
    unicode_put(bytes+(d->is64?0x38u:0x24u),&d->current_directory,width);
    unicode_put(bytes+(d->is64?0x50u:0x30u),&d->dll_path,width);
    unicode_put(bytes+(d->is64?0x60u:0x38u),&d->image_path,width);
    unicode_put(bytes+(d->is64?0x70u:0x40u),&d->command_line,width);
    put(bytes+(d->is64?0x80u:0x48u),width,d->environment);
    put(bytes+(d->is64?0x3f0u:0x290u),width,d->environment_bytes);
    return store(m,d->parameters,bytes,l->parameters_size,width)?XXEMUL_STATUS_OK:XXEMUL_STATUS_ADDRESS_FAULT;
}

xxemul_status xxemul_windows_process_update_heaps(
 const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d)
{
    uint8_t peb[0x800],heaps[64u*8u];unsigned i,width;xxemul_status status=process_valid(m,d);
    const xxemul_windows_process_layout*l;
    if(status!=XXEMUL_STATUS_OK)return status;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;
    if(!load(m,d->peb,peb,l->peb_size,width)||!load(m,d->heap_list,heaps,d->heap_capacity*width,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    memset(heaps,0,d->heap_capacity*width);
    for(i=0u;i<d->heap_count;++i){uint64_t heap=d->heaps?d->heaps[i]:d->heap;
        if(!address_valid(heap,MODEL_HEAP_BYTES,width))return XXEMUL_STATUS_INVALID_ARGUMENT;
        if(!probe(m,heap,MODEL_HEAP_BYTES,width))return XXEMUL_STATUS_ADDRESS_FAULT;
        put(heaps+i*width,width,heap);}
    put(peb+l->process_heap,width,d->heap);put(peb+l->number_of_heaps,4u,d->heap_count);
    put(peb+l->maximum_number_of_heaps,4u,d->heap_capacity);put(peb+l->process_heaps,width,d->heap_list);
    if(!store(m,d->heap_list,heaps,d->heap_capacity*width,width)||!store(m,d->peb,peb,l->peb_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_process_update_tls_bitmap(
 const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d,
 const uint32_t*allocated_bits,uint32_t allocated_dwords)
{
    uint8_t peb[0x800],bitmap[16]={0},expansion[16]={0};unsigned i,width,needed;
    const xxemul_windows_process_layout*l;xxemul_status status=process_valid(m,d);
    if(status!=XXEMUL_STATUS_OK)return status;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;needed=(d->tls_capacity+31u)/32u;
    if((allocated_dwords&&!allocated_bits)||allocated_dwords>needed)return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(!load(m,d->peb,peb,l->peb_size,width)||!load(m,d->tls_bitmap,bitmap,width==8u?16u:8u,width)||
        !load(m,d->tls_expansion_bitmap,expansion,width==8u?16u:8u,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    memset(peb+l->tls_bitmap_bits,0,8u);memset(peb+l->tls_expansion_bitmap_bits,0,128u);
    for(i=0u;i<allocated_dwords;++i){unsigned offset=i<2u?l->tls_bitmap_bits+i*4u:l->tls_expansion_bitmap_bits+(i-2u)*4u;
        uint32_t value=allocated_bits[i];
        if(i==needed-1u&&(d->tls_capacity&31u))value&=(1u<<(d->tls_capacity&31u))-1u;
        put(peb+offset,4u,value);}
    memset(bitmap,0,sizeof(bitmap));memset(expansion,0,sizeof(expansion));
    put(bitmap,4u,64u);put(bitmap+(width==8u?8u:4u),width,d->peb+l->tls_bitmap_bits);
    put(expansion,4u,d->tls_capacity-64u);put(expansion+(width==8u?8u:4u),width,d->peb+l->tls_expansion_bitmap_bits);
    put(peb+l->tls_bitmap,width,d->tls_bitmap);put(peb+l->tls_expansion_bitmap,width,d->tls_expansion_bitmap);
    if(!store(m,d->tls_bitmap,bitmap,width==8u?16u:8u,width)||!store(m,d->tls_expansion_bitmap,expansion,width==8u?16u:8u,width)||
        !store(m,d->peb,peb,l->peb_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_process_update_exception_flags(
 const xxemul_windows_process_memory*m,int is64,uint64_t peb,int initializing,int using_veh,int using_vch)
{
    uint8_t bytes[4];unsigned width=is64?8u:4u;uint64_t address;uint32_t flags;
    if(peb>UINT64_MAX-(is64?0x50u:0x28u))return XXEMUL_STATUS_INVALID_ARGUMENT;
    address=peb+(is64?0x50u:0x28u);
    if(!load(m,address,bytes,4u,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    flags=(uint32_t)get(bytes,4u);flags&=~14u;
    flags|=(initializing?2u:0u)|(using_veh?4u:0u)|(using_vch?8u:0u);put(bytes,4u,flags);
    return store(m,address,bytes,4u,width)?XXEMUL_STATUS_OK:XXEMUL_STATUS_ADDRESS_FAULT;
}

static int initialize_lock(const xxemul_windows_process_memory*m,uint64_t address,unsigned width)
{
    uint8_t bytes[40];unsigned size=width==8u?40u:24u;
    if(!address)return 1;
    if(!load(m,address,bytes,size,width))return 0;
    memset(bytes,0,size);put(bytes+width,4u,UINT32_MAX);
    return store(m,address,bytes,size,width);
}

xxemul_status xxemul_windows_process_initialize_heap(const xxemul_windows_process_memory*m,int is64,
 uint64_t address,uint64_t start,uint64_t limit,uint32_t flags,uint32_t force)
{
    uint8_t heap[MODEL_HEAP_BYTES];const xxemul_windows_process_layout*l=xxemul_windows_process_get_layout(is64);
    unsigned width=l->pointer_size;
    if(!pointer_valid(start,width)||!pointer_valid(limit,width)||start>=limit||
        limit-start>UINT64_C(0xffffffff)*0x1000u)return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(!load(m,address,heap,sizeof(heap),width))return XXEMUL_STATUS_ADDRESS_FAULT;
    memset(heap,0,sizeof(heap));put(heap+(is64?0x10u:8u),4u,NT_HEAP_SEGMENT_SIGNATURE);
    put(heap+(is64?0x28u:0x18u),width,address);put(heap+(is64?0x30u:0x1cu),width,start);
    put(heap+(is64?0x38u:0x20u),4u,((limit-start)+0xfffu)/0x1000u);
    put(heap+(is64?0x40u:0x24u),width,start);put(heap+(is64?0x48u:0x28u),width,limit);
    put(heap+l->heap_flags,4u,flags);put(heap+l->heap_force_flags,4u,force);
    put(heap+MODEL_HEAP_META,4u,MODEL_HEAP_SIGNATURE);put(heap+MODEL_HEAP_META+4u,4u,1u);
    put(heap+MODEL_HEAP_META+8u,8u,start);put(heap+MODEL_HEAP_META+16u,8u,limit);
    return store(m,address,heap,sizeof(heap),width)?XXEMUL_STATUS_OK:XXEMUL_STATUS_ADDRESS_FAULT;
}

xxemul_status xxemul_windows_process_initialize(
 const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d)
{
    uint8_t peb[0x800],heap[MODEL_HEAP_BYTES],loader[0x58];unsigned width,subsystem,index;
    const xxemul_windows_process_layout*l;xxemul_status status=process_valid(m,d);
    if(status!=XXEMUL_STATUS_OK)return status;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;
    /* Preflight all referenced allocations before publishing this process. */
    if(!parameter_payloads(m,d,width)||!probe(m,d->image_base,1u,width)||
        !probe(m,d->parameters,l->parameters_size,width)||!probe(m,d->heap_list,d->heap_capacity*width,width)||
        !probe(m,d->tls_bitmap,width==8u?16u:8u,width)||!probe(m,d->tls_expansion_bitmap,width==8u?16u:8u,width)||
        (d->fast_peb_lock&&!probe(m,d->fast_peb_lock,width==8u?40u:24u,width))||
        (d->loader_lock&&!probe(m,d->loader_lock,width==8u?40u:24u,width)))return XXEMUL_STATUS_ADDRESS_FAULT;
    for(index=0u;index<d->heap_count;++index){uint64_t address=d->heaps?d->heaps[index]:d->heap;
        if(!address_valid(address,MODEL_HEAP_BYTES,width))return XXEMUL_STATUS_INVALID_ARGUMENT;
        if(!probe(m,address,MODEL_HEAP_BYTES,width))return XXEMUL_STATUS_ADDRESS_FAULT;}
    if(!load(m,d->peb,peb,l->peb_size,width)||!load(m,d->heap,heap,sizeof(heap),width)||
        !load(m,d->loader,loader,d->is64?0x58u:0x30u,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    peb[0]=(uint8_t)!!d->inherited_address_space;peb[1]=0u;peb[2]=(uint8_t)!!d->being_debugged;
    put(peb+l->image_base,width,d->image_base);put(peb+l->loader,width,d->loader);put(peb+l->parameters,width,d->parameters);
    put(peb+l->fast_peb_lock,width,d->fast_peb_lock);put(peb+l->loader_lock,width,d->loader_lock);
    put(peb+(d->is64?0xb8u:0x64u),4u,d->processor_count);put(peb+l->global_flags,4u,d->global_flags);
    put(peb+l->os_major,4u,d->major_version);put(peb+l->os_minor,4u,d->minor_version);put(peb+l->os_build,2u,d->build_number);
    put(peb+l->os_build+2u,2u,0u);put(peb+l->os_platform,4u,d->platform_id);put(peb+l->session_id,4u,d->session_id);
    subsystem=d->is64?0x128u:0xb4u;
    put(peb+subsystem,4u,d->subsystem);put(peb+subsystem+4u,4u,d->subsystem_major);put(peb+subsystem+8u,4u,d->subsystem_minor);
    put(peb+(d->is64?0x138u:0xc0u),width,d->affinity_mask);
    put(loader,4u,d->is64?0x58u:0x30u);loader[4]=(uint8_t)!!d->loader_initialized;
    status=xxemul_windows_process_initialize_heap(m,d->is64,d->heap,d->heap_start,d->heap_limit,d->heap_flags,d->heap_force_flags);
    if(status!=XXEMUL_STATUS_OK)return status;
    if(!initialize_lock(m,d->fast_peb_lock,width)||!initialize_lock(m,d->loader_lock,width)||
        !store(m,d->loader,loader,d->is64?0x58u:0x30u,width)||
        !store(m,d->peb,peb,l->peb_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    status=xxemul_windows_process_update_parameters(m,d);if(status!=XXEMUL_STATUS_OK)return status;
    status=xxemul_windows_process_update_heaps(m,d);if(status!=XXEMUL_STATUS_OK)return status;
    status=xxemul_windows_process_update_tls_bitmap(m,d,NULL,0u);if(status!=XXEMUL_STATUS_OK)return status;
    return xxemul_windows_process_update_exception_flags(m,d->is64,d->peb,(int)d->process_initializing,
        (int)d->using_vectored_exceptions,(int)d->using_vectored_continue);
}

xxemul_status xxemul_windows_thread_update_tls(
 const xxemul_windows_process_memory*m,const xxemul_windows_thread_description*d)
{
    uint8_t base[64u*8u],expanded[1024u*8u],pointer[8];unsigned i,width;
    const xxemul_windows_process_layout*l;
    if(!m||!d||!m->read||!m->write||d->tls_count>1088u||(d->tls_count&&!d->tls_values))return XXEMUL_STATUS_INVALID_ARGUMENT;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;
    if(!address_valid(d->teb,l->teb_size,width)||d->teb>UINT64_MAX-l->tls_slots)return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(!load(m,d->teb+l->tls_slots,base,64u*width,width)||
        (d->tls_count>64u&&!load(m,d->tls_expansion,expanded,(d->tls_count-64u)*width,width)))return XXEMUL_STATUS_ADDRESS_FAULT;
    memset(base,0,64u*width);if(d->tls_count>64u)memset(expanded,0,(d->tls_count-64u)*width);
    for(i=0u;i<d->tls_count;++i){if(!pointer_valid(d->tls_values[i],width))return XXEMUL_STATUS_INVALID_ARGUMENT;
        put(i<64u?base+i*width:expanded+(i-64u)*width,width,d->tls_values[i]);}
    put(pointer,width,d->tls_count>64u?d->tls_expansion:0u);
    if(!store(m,d->teb+l->tls_slots,base,64u*width,width)||
        (d->tls_count>64u&&!store(m,d->tls_expansion,expanded,(d->tls_count-64u)*width,width))||
        !store(m,d->teb+l->tls_expansion,pointer,width,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_thread_update_errors(const xxemul_windows_process_memory*m,int is64,uint64_t teb,
 uint32_t last_error,uint32_t last_status)
{
    const xxemul_windows_process_layout*l=xxemul_windows_process_get_layout(is64);uint8_t error[4],status[4],old[4];
    if(!address_valid(teb,l->teb_size,l->pointer_size))return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(!load(m,teb+l->last_error,old,4u,l->pointer_size)||!load(m,teb+l->last_status,old,4u,l->pointer_size))return XXEMUL_STATUS_ADDRESS_FAULT;
    put(error,4u,last_error);put(status,4u,last_status);
    if(!store(m,teb+l->last_error,error,4u,l->pointer_size)||!store(m,teb+l->last_status,status,4u,l->pointer_size))return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_thread_initialize(
 const xxemul_windows_process_memory*m,const xxemul_windows_thread_description*d)
{
    uint8_t teb[0x2000];unsigned width,index;
    const xxemul_windows_process_layout*l;xxemul_status status;
    if(!d||!m||!m->read||!m->write)return XXEMUL_STATUS_INVALID_ARGUMENT;
    l=xxemul_windows_process_get_layout(d->is64);width=l->pointer_size;
    if(d->stack_base<=d->stack_limit||!pointer_valid(d->stack_base,width)||!pointer_valid(d->stack_limit,width)||
        !pointer_valid(d->deallocation_stack,width)||!pointer_valid(d->peb,width)||!d->peb||
        !pointer_valid(d->process_id,width)||!pointer_valid(d->thread_id,width)||!pointer_valid(d->static_tls,width)||
        (width==4u&&d->exception_list!=UINT64_MAX&&!pointer_valid(d->exception_list,width)))return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(d->tls_count>1088u||(d->tls_count&&!d->tls_values))return XXEMUL_STATUS_INVALID_ARGUMENT;
    for(index=0u;index<d->tls_count;++index)if(!pointer_valid(d->tls_values[index],width))return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(!probe(m,d->peb,l->peb_size,width)||(d->static_tls&&!probe(m,d->static_tls,width,width))||
        !probe(m,d->stack_limit,1u,width)||!probe(m,d->stack_base-1u,1u,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(d->tls_count>64u&&!probe(m,d->tls_expansion,(d->tls_count-64u)*width,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(!load(m,d->teb,teb,l->teb_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    memset(teb,0,l->teb_size);
    put(teb,width,d->exception_list);put(teb+l->tib_stack_base,width,d->stack_base);put(teb+l->tib_stack_limit,width,d->stack_limit);
    put(teb+l->tib_self,width,d->teb);put(teb+l->client_id,width,d->process_id);put(teb+l->client_id+width,width,d->thread_id);
    put(teb+l->static_tls,width,d->static_tls);put(teb+l->peb_pointer,width,d->peb);
    put(teb+l->last_error,4u,d->last_error);put(teb+l->last_status,4u,d->last_status);
    put(teb+l->deallocation_stack,width,d->deallocation_stack);put(teb+(d->is64?0x108u:0xc4u),4u,d->locale);
    if(!store(m,d->teb,teb,l->teb_size,width))return XXEMUL_STATUS_ADDRESS_FAULT;
    status=xxemul_windows_thread_update_tls(m,d);
    return status;
}

xxemul_status xxemul_windows_process_validate_heap(
 const xxemul_windows_process_memory*m,const xxemul_windows_process_description*d,int*valid)
{
    uint8_t bytes[MODEL_HEAP_BYTES];const xxemul_windows_process_layout*l;
    if(!d||!valid)return XXEMUL_STATUS_INVALID_ARGUMENT;
    l=xxemul_windows_process_get_layout(d->is64);
    if(!load(m,d->heap,bytes,sizeof(bytes),l->pointer_size))return XXEMUL_STATUS_ADDRESS_FAULT;
    *valid=get(bytes+(d->is64?0x10u:8u),4u)==NT_HEAP_SEGMENT_SIGNATURE&&
        get(bytes+l->heap_flags,4u)==d->heap_flags&&get(bytes+l->heap_force_flags,4u)==d->heap_force_flags&&
        get(bytes+MODEL_HEAP_META,4u)==MODEL_HEAP_SIGNATURE&&get(bytes+MODEL_HEAP_META+4u,4u)==1u&&
        get(bytes+MODEL_HEAP_META+8u,8u)==d->heap_start&&get(bytes+MODEL_HEAP_META+16u,8u)==d->heap_limit;
    return XXEMUL_STATUS_OK;
}
