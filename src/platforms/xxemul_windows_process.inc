/* Bounded independent Windows guest processes. Never spawn a host executable. */
static win_child_process *win_child_at(xxemul_windows *process, const win_handle *handle)
{
    if (!handle || !handle->child_slot || handle->child_slot > WIN_MAX_CHILDREN) return NULL;
    return process->children[handle->child_slot-1u].active ? &process->children[handle->child_slot-1u] : NULL;
}

static int win_child_referenced(const xxemul_windows *process, size_t slot)
{
    size_t i;
    for (i=0u;i<WIN_MAX_HANDLES;++i)
        if (process->handles[i].in_use && process->handles[i].kind!=WIN_HANDLE_ALIAS &&
            process->handles[i].child_slot==slot+1u && process->handles[i].references) return 1;
    return 0;
}

static void win_child_output(void *context, int stream, const void *bytes, size_t size)
{
    xxemul_windows *parent=(xxemul_windows*)context;
    if(!xxemul_emit_output(parent->emulator,stream,bytes,size) && size)
        (void)fwrite(bytes,1u,size,stream==2?stderr:stdout);
}

static void win_child_discard(xxemul_windows *process, win_child_process *child)
{
    if (child->emulator) {
        uint64_t memory=child->emulator->region_size;
        xxemul_destroy(child->emulator);
        if (process->process_tree) {
            process->process_tree->memory-=memory;
            --process->process_tree->processes;
        }
    }
    memset(child,0,sizeof(*child));
}

static void win_children_destroy(xxemul_windows *process)
{
    size_t i;
    for(i=0u;i<WIN_MAX_CHILDREN;++i) if(process->children[i].active) win_child_discard(process,&process->children[i]);
    if(process->tree_owner) free(process->process_tree);
}

static int win_child_threads_runnable(const win_child_process *child)
{
    size_t i;
    if(!child->emulator || child->finished)return 0;
    for(i=0u;i<WIN_MAX_THREADS;++i)
        if(child->emulator->windows->threads[i].active && !child->emulator->windows->threads[i].suspended)return 1;
    return 0;
}

static void win_child_finish(win_child_process *child, uint32_t code)
{
    xxemul_windows *process=child->emulator->windows;
    size_t i;
    /* End the guest process's kernel-object ownership before signaling the
     * parent. The retained process/thread objects only carry exit information. */
    for(i=0u;i<WIN_MAX_HANDLES;++i) {
        win_handle *entry=&process->handles[i];
        if(entry->kind==WIN_HANDLE_MAPPING && entry->view_address)
            (void)win_mapping_flush(process,entry,entry->view_address,0u);
        if(entry->io)xx_io_close(entry->io);
        win_find_destroy(entry->find);free(entry->mapping_data);
    }
    memset(process->handles,0,sizeof(process->handles));
    for(i=0u;i<WIN_MAX_THREADS;++i) {
        win_tls_thread_release(process,&process->threads[i]);
        if(process->threads[i].active) {
            process->threads[i].active=0u;process->threads[i].exit_code=code;
        }
    }
    process->exit_code=code;process->process_terminated=1u;
    child->emulator->halted=1u;child->emulator->exit_code=(uint8_t)code;
    child->exit_code=code;child->finished=1u;
}

static int win_children_runnable(const xxemul_windows *process)
{
    size_t i;
    for(i=0u;i<WIN_MAX_CHILDREN;++i) {
        const win_child_process *child=&process->children[i];
        if(child->active && !child->failure && (win_child_threads_runnable(child) ||
           (child->emulator && child->emulator->windows && win_children_runnable(child->emulator->windows)))) return 1;
    }
    return 0;
}

static xxemul_status win_children_pump(xxemul_windows *process, unsigned quantum)
{
    size_t i;
    for(i=0u;i<WIN_MAX_CHILDREN;++i) {
        win_child_process *child=&process->children[i];
        unsigned n;
        if(!child->active) continue;
        if(child->failure) return child->failure;
        if(child->finished) {
            if(child->emulator && child->emulator->windows) {
                xxemul_status nested=win_children_pump(child->emulator->windows,quantum);
                if(nested!=XXEMUL_STATUS_OK) return nested;
            }
            if(!win_child_referenced(process,i) && (!child->emulator || !win_children_runnable(child->emulator->windows)))
                win_child_discard(process,child);
            continue;
        }
        if(!win_child_threads_runnable(child)) continue;
        if(child->emulator->windows->threads[child->emulator->windows->thread_current].suspended) {
            xxemul_status switched=win_thread_yield(child->emulator->windows,NULL);
            if(switched!=XXEMUL_STATUS_OK){child->failure=switched;return switched;}
        }
        for(n=0u;n<quantum;++n) {
            xxemul_status status;
            if(++child->steps>UINT64_C(0x40000000)) { child->failure=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return child->failure; }
            status=xxemul_step(child->emulator,NULL);
            if(status==XXEMUL_STATUS_HALTED && child->emulator->windows->process_terminated) {
                win_child_finish(child,xxemul_windows_exit_code(child->emulator->windows));
                break;
            }
            if(status!=XXEMUL_STATUS_OK) {
                /* An emulator limitation or arbitrary HLT is not a fabricated
                 * successful process exit. Preserve it as an execution error. */
                child->failure=status==XXEMUL_STATUS_HALTED?XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION:status;
                return child->failure;
            }
        }
    }
    return XXEMUL_STATUS_OK;
}

static int win_child_arguments(const char *command, char *storage, size_t capacity, const char **argv, size_t *argc)
{
    const char *p=command;
    size_t used=0u,count=0u;
    while(*p) {
        int quoted=0;
        while(*p==' ' || *p=='\t') ++p;
        if(!*p) break;
        if(count>=127u) return 0;
        argv[count++]=storage+used;
        while(*p && (quoted || (*p!=' ' && *p!='\t'))) {
            size_t slashes=0u,j;
            while(*p=='\\') { ++slashes; ++p; }
            if(*p=='"') {
                for(j=0u;j<slashes/2u;++j) { if(used+1u>=capacity)return 0;storage[used++]='\\'; }
                if(slashes&1u) { if(used+1u>=capacity)return 0;storage[used++]='"';++p; }
                else if(quoted && p[1]=='"') { if(used+1u>=capacity)return 0;storage[used++]='"';p+=2; }
                else { quoted=!quoted; ++p; }
            } else {
                for(j=0u;j<slashes;++j) { if(used+1u>=capacity)return 0;storage[used++]='\\'; }
                if(!*p || (!quoted && (*p==' ' || *p=='\t'))) break;
                if(used+1u>=capacity)return 0;
                storage[used++]=*p++;
            }
        }
        if(quoted || used>=capacity) return 0;
        storage[used++]=0;
    }
    argv[count]=NULL; *argc=count; return count!=0u;
}

static int win_child_security(xxemul_windows *process, uint64_t pointer, uint32_t *inherit)
{
    uint8_t width=win_word_size(process->emulator);
    uint64_t length,descriptor,value;
    *inherit=0u;
    if(!pointer)return 1;
    if(!win_load(process,pointer,4u,&length) || length!=(width==8u?24u:12u) ||
       !win_load(process,pointer+(width==8u?8u:4u),width,&descriptor) ||
       !win_load(process,pointer+(width==8u?16u:8u),4u,&value)) { process->last_error=87u;return 0; }
    if(descriptor) { process->last_error=50u;return 0; }
    *inherit=value!=0u;return 1;
}

static int win_child_environment(xxemul_windows *parent, xxemul_windows *child, uint64_t source, int wide)
{
    char block[WIN_ENV_MAX_BYTES];size_t used=0u,entries=0u;
    if(!source) {
        memcpy(child->environment_data,parent->environment_data,parent->environment_size);
        child->environment_size=parent->environment_size;
        return win_sync_environment(child);
    }
    for(;;) {
        char entry[WIN_ENV_MAX_BYTES];size_t length;
        if(!win_environment_text(parent,source,wide,entry,sizeof(entry))) return 0;
        length=strlen(entry);
        if(!length) { if(!used)block[used++]=0;block[used++]=0;break; }
        if(!strchr(entry,'=') || entry[0]=='=' || ++entries>WIN_ENV_MAX_ENTRIES ||
           length+2u>sizeof(block)-used) { parent->last_error=87u;return 0; }
        memcpy(block+used,entry,length+1u);used+=length+1u;
        /* The current environment model is CP1252/ASCII. Count source UTF16
         * units explicitly rather than advancing by encoded UTF8 length. */
        if(wide) {
            uint64_t character;size_t units=0u;
            do { if(!win_load(parent,source+units*2u,2u,&character)||units>=WIN_ENV_MAX_BYTES) { parent->last_error=998u;return 0; }++units; }while(character);
            source+=units*2u;
        } else source+=length+1u;
    }
    memcpy(child->environment_data,block,used);child->environment_size=used;
    return win_sync_environment(child);
}

static int win_child_program(xxemul_windows *process, const char *application, char *host, size_t capacity)
{
    char candidate[1024],directory[1024];const char *at;size_t length;
    if(!application || !*application || !win_copy(candidate,sizeof(candidate),application)) return 0;
    length=strlen(candidate);
    at=strrchr(candidate,'\\');if(!at)at=strrchr(candidate,'/');if(!at)at=candidate;
    if(!strchr(at,'.')) { if(length+5u>sizeof(candidate))return 0;memcpy(candidate+length,".exe",5u); }
    /* Search the executable's directory, then the guest CWD.
     * Guest system directories and PATH search are not modeled. */
    if(!strpbrk(candidate,"/\\:")) {
        const char *last=process->program_path;
        for(at=last;*at;++at)if(*at=='/'||*at=='\\')last=at;
        length=(size_t)(last-process->program_path);
        if(length && length+strlen(candidate)+2u<=sizeof(directory)) {
            memcpy(directory,process->program_path,length);directory[length]='/';strcpy(directory+length+1u,candidate);
            if(win_guest_path(process,directory,host,capacity) && xx_io_file_exists_a(host))return 1;
        }
    }
    if(win_guest_path(process,candidate,host,capacity) && xx_io_file_exists_a(host))return 1;
    return 0;
}

static xxemul_status win_create_process(xxemul_windows *process, const uint64_t *arg, int wide, uint64_t *result)
{
    char command[2048],application[1024],storage[2048],host[2048],cwd[1024];
    const char *argv[128];size_t argc=0u,slot,process_slot,thread_slot,i;
    uint8_t width=win_word_size(process->emulator);uint32_t process_inherit,thread_inherit;
    uint64_t startup_size,startup_flags,value,flags=(uint32_t)arg[5];
    xxemul *emulator=NULL;xxemul_windows *child_process;xxemul_status status;
    win_child_process *child;xx_io_device *file;uint8_t dos[64],header[26];uint32_t nt;xxemul_image_format format;
    *result=0u;
    if(process->emulator->arch!=XXEMUL_ARCH_X86 || process->process_depth>=4u) { process->last_error=50u;return XXEMUL_STATUS_OK; }
    if(!arg[9] || !win_memory_span(process,arg[9],width*2u+8u) || !arg[8] ||
       !win_load(process,arg[8],4u,&startup_size) || startup_size!=(width==8u?104u:68u) ||
       !win_memory_span(process,arg[8],startup_size)) { process->last_error=998u;return XXEMUL_STATUS_OK; }
    if(flags&~UINT64_C(0x08000404)) { process->last_error=50u;return XXEMUL_STATUS_OK; }
    if(!win_child_security(process,arg[2],&process_inherit) || !win_child_security(process,arg[3],&thread_inherit))return XXEMUL_STATUS_OK;
    if(!win_load(process,arg[8]+(width==8u?60u:44u),4u,&startup_flags)) { process->last_error=998u;return XXEMUL_STATUS_OK; }
    if(startup_flags&~UINT64_C(0x101)) { process->last_error=50u;return XXEMUL_STATUS_OK; }
    if(startup_flags&0x100u) for(i=0u;i<3u;++i) {
        if(!win_load(process,arg[8]+(width==8u?80u:56u)+i*width,width,&value) || value!=0x10u+i) {
            process->last_error=50u;return XXEMUL_STATUS_OK;
        }
    }
    if(arg[4]) for(i=0u;i<WIN_MAX_HANDLES;++i) if(process->handles[i].in_use && process->handles[i].flags&1u) {
        process->last_error=50u;return XXEMUL_STATUS_OK;
    }
    command[0]=application[0]=0;
    if(arg[1] && !win_guest_string(process,arg[1],command,sizeof(command),wide)) { process->last_error=998u;return XXEMUL_STATUS_OK; }
    if(arg[0] && !win_guest_string(process,arg[0],application,sizeof(application),wide)) { process->last_error=998u;return XXEMUL_STATUS_OK; }
    if(!command[0]) {
        size_t length=0u;
        if(!application[0] || !win_append_quoted(command,sizeof(command),&length,application)) { process->last_error=87u;return XXEMUL_STATUS_OK; }
    }
    if(!win_child_arguments(command,storage,sizeof(storage),argv,&argc)) { process->last_error=87u;return XXEMUL_STATUS_OK; }
    if(!application[0] && !win_copy(application,sizeof(application),argv[0])) { process->last_error=206u;return XXEMUL_STATUS_OK; }
    if(!win_child_program(process,application,host,sizeof(host))) { process->last_error=2u;return XXEMUL_STATUS_OK; }
    if(arg[7]) {
        if(!win_guest_string(process,arg[7],cwd,sizeof(cwd),wide)) { process->last_error=998u;return XXEMUL_STATUS_OK; }
    } else if(!win_copy(cwd,sizeof(cwd),process->guest_directory)) { process->last_error=206u;return XXEMUL_STATUS_OK; }
    file=xx_io_file_open(host,"rb");
    if(!file) { process->last_error=2u;return XXEMUL_STATUS_OK; }
    if(xx_io_read(file,dos,sizeof(dos))!=(ssize_t)sizeof(dos) || dos[0]!='M'||dos[1]!='Z') {xx_io_close(file);process->last_error=193u;return XXEMUL_STATUS_OK;}
    nt=win_le32(dos+60u);
    if(nt>UINT32_C(0x100000) || xx_io_seek64(file,nt,SEEK_SET)!=0 ||
       xx_io_read(file,header,sizeof(header))!=(ssize_t)sizeof(header) || memcmp(header,"PE\0\0",4u) ||
       (win_le16(header+22u)&0x2000u) ||
       !((win_le16(header+4u)==0x14cu&&win_le16(header+24u)==0x10bu)||
         (win_le16(header+4u)==0x8664u&&win_le16(header+24u)==0x20bu))) {
        xx_io_close(file);process->last_error=193u;return XXEMUL_STATUS_OK;
    }
    format=win_le16(header+24u)==0x20bu?XXEMUL_IMAGE_PE64:XXEMUL_IMAGE_PE32;xx_io_close(file);
    for(slot=0u;slot<WIN_MAX_CHILDREN;++slot) {
        child=&process->children[slot];
        if(child->active&&child->finished&&!win_child_referenced(process,slot)&&!win_children_runnable(child->emulator->windows))win_child_discard(process,child);
        if(!child->active)break;
    }
    process_slot=thread_slot=WIN_MAX_HANDLES;
    for(i=0u;i<WIN_MAX_HANDLES;++i)if(!process->handles[i].in_use) {if(process_slot==WIN_MAX_HANDLES)process_slot=i;else{thread_slot=i;break;}}
    if(slot==WIN_MAX_CHILDREN || thread_slot==WIN_MAX_HANDLES) { process->last_error=4u;return XXEMUL_STATUS_OK; }
    if(!process->process_tree) {
        process->process_tree=(win_process_tree*)calloc(1,sizeof(*process->process_tree));
        if(!process->process_tree) { process->last_error=8u;return XXEMUL_STATUS_OK; }
        process->tree_owner=1u;process->process_tree->processes=1u;
        process->process_tree->memory=process->emulator->region_size;
        process->process_tree->next_id=process->next_thread_id>0x1000u?process->next_thread_id:0x1000u;
    }
    if(process->process_tree->processes>=8u || process->process_tree->next_id>UINT32_MAX-2u) {process->last_error=8u;return XXEMUL_STATUS_OK;}
    emulator=xxemul_create_image_file(format,host,&status);
    if(!emulator) { process->last_error=status==XXEMUL_STATUS_OUT_OF_MEMORY?8u:193u;return XXEMUL_STATUS_OK; }
    if(emulator->region_size>UINT64_C(0x10000000)-process->process_tree->memory) {
        xxemul_destroy(emulator);process->last_error=8u;return XXEMUL_STATUS_OK;
    }
    status=xxemul_start_process(emulator,format,host,process->working_directory,(int)argc,argv);
    if(status!=XXEMUL_STATUS_OK) {xxemul_destroy(emulator);process->last_error=193u;return XXEMUL_STATUS_OK;}
    child_process=emulator->windows;
    child_process->startup_flags=(uint32_t)startup_flags;
    if(startup_flags&1u) {
        (void)win_load(process,arg[8]+(width==8u?64u:48u),2u,&value);
        child_process->startup_show=(uint16_t)value;
    }
    (void)win_copy(child_process->guest_directory,sizeof(child_process->guest_directory),process->guest_directory);
    if(!win_set_guest_directory(child_process,cwd)) {
        uint32_t error=child_process->last_error;xxemul_destroy(emulator);process->last_error=error;return XXEMUL_STATUS_OK;
    }
    if(!win_child_environment(process,child_process,arg[6],(flags&0x400u)!=0u)) {
        xxemul_destroy(emulator);return XXEMUL_STATUS_OK;
    }
    if(!win_write(child_process,child_process->command_line_a,command,strlen(command)+1u) ||
       !win_write_wide(child_process,child_process->command_line_w,command,2048u)) {
        xxemul_destroy(emulator);process->last_error=8u;return XXEMUL_STATUS_OK;
    }
    {
        uint8_t child_width=win_word_size(emulator);
        uint64_t descriptor=child_process->runtime_base+0x4000u+(child_width==8u?0x70u:0x40u);
        uint64_t cursor=child_process->runtime_base+WIN_CRT_STRINGS_OFFSET;
        (void)win_store(child_process,descriptor,2u,strlen(command)*2u);
        (void)win_store(child_process,descriptor+2u,2u,(strlen(command)+1u)*2u);
        for(i=0u;i<argc;++i) {
            size_t size=strlen(argv[i])+1u;
            if(!win_write(child_process,cursor,argv[i],size) ||
               !win_store(child_process,child_process->argv_address+i*child_width,child_width,cursor)) {
                xxemul_destroy(emulator);process->last_error=8u;return XXEMUL_STATUS_OK;
            }
            cursor+=size;
        }
    }
    xxemul_set_output_callback(emulator,win_child_output,process);
    child=&process->children[slot];memset(child,0,sizeof(*child));
    child->active=1u;child->emulator=emulator;child->suspended=(flags&4u)!=0u;
    child_process->threads[0].suspended=child->suspended;
    child->process_id=++process->process_tree->next_id;child->thread_id=++process->process_tree->next_id;
    child_process->process_tree=process->process_tree;child_process->process_depth=process->process_depth+1u;
    child_process->process_id=child->process_id;child_process->threads[0].id=child->thread_id;
    child_process->next_thread_id=child->thread_id;
    ++process->process_tree->processes;process->process_tree->memory+=emulator->region_size;
    (void)win_store(child_process,child_process->runtime_base+(win_word_size(emulator)==8u?0x40u:0x20u),win_word_size(emulator),child->process_id);
    (void)win_store(child_process,child_process->runtime_base+(win_word_size(emulator)==8u?0x48u:0x24u),win_word_size(emulator),child->thread_id);
    for(i=0u;i<2u;++i) {
        size_t h=i?thread_slot:process_slot;win_handle *entry=&process->handles[h];
        memset(entry,0,sizeof(*entry));entry->in_use=1u;entry->references=1u;entry->root_slot=(uint16_t)h;
        entry->kind=i?WIN_HANDLE_THREAD:WIN_HANDLE_PROCESS;entry->child_slot=(uint16_t)(slot+1u);
        entry->flags=i?thread_inherit:process_inherit;
    }
    (void)win_store(process,arg[9],width,0x100u+process_slot);
    (void)win_store(process,arg[9]+width,width,0x100u+thread_slot);
    (void)win_store(process,arg[9]+width*2u,4u,child->process_id);
    (void)win_store(process,arg[9]+width*2u+4u,4u,child->thread_id);
    process->child_tick=1u;*result=1u;return XXEMUL_STATUS_OK;
}
