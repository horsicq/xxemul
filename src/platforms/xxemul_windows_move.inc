/* Same-filesystem no-overwrite rename. Parent directories remain anchored by
 * no-follow descriptors until the host rename commits. */
static int win_move_path_matches(const char *path,const char *from,int directory)
{
    size_t length=strlen(from);
    return !strcmp(path,from)||(directory&&!strncmp(path,from,length)&&path[length]=='/');
}
static int win_move_paths_fit(xxemul_windows *process,const char *from,const char *to,int directory)
{
    size_t index,old_length=strlen(from),new_length=strlen(to);
    for(index=0u;index<WIN_MAX_HANDLES;++index){
        win_handle *entry=&process->handles[index];
        if(entry->in_use&&win_move_path_matches(entry->file_path,from,directory)&&
           new_length+strlen(entry->file_path+old_length)>=sizeof(entry->file_path))return 0;
    }
    for(index=0u;index<WIN_FILE_ATTRIBUTE_SLOTS;++index){
        win_file_attribute *entry=&process->file_attributes[index];
        if(entry->used&&win_move_path_matches(entry->path,from,directory)&&
           new_length+strlen(entry->path+old_length)>=sizeof(entry->path))return 0;
    }
    return 1;
}
static void win_move_paths_commit(xxemul_windows *process,const char *from,const char *to,int directory)
{
    size_t index,old_length=strlen(from),new_length=strlen(to);
    for(index=0u;index<WIN_FILE_ATTRIBUTE_SLOTS;++index)
        if(process->file_attributes[index].used&&win_move_path_matches(process->file_attributes[index].path,to,directory))
            process->file_attributes[index].used=0u;
    for(index=0u;index<WIN_MAX_HANDLES;++index){
        win_handle *entry=&process->handles[index];
        if(entry->in_use&&win_move_path_matches(entry->file_path,from,directory)){
            memmove(entry->file_path+new_length,entry->file_path+old_length,strlen(entry->file_path+old_length)+1u);
            memcpy(entry->file_path,to,new_length);
        }
    }
    for(index=0u;index<WIN_FILE_ATTRIBUTE_SLOTS;++index){
        win_file_attribute *entry=&process->file_attributes[index];
        if(entry->used&&win_move_path_matches(entry->path,from,directory)){
            memmove(entry->path+new_length,entry->path+old_length,strlen(entry->path+old_length)+1u);
            memcpy(entry->path,to,new_length);
        }
    }
}
#if !defined(_WIN32)
static int win_move_parent(xxemul_windows *process,const char *host,char *leaf,size_t capacity)
{
    char root[2048],relative[2048],*part,*next;size_t length;int directory,saved;
    if(!win_working_root(process,root,sizeof(root))){errno=ENOENT;return -1;}
    length=strlen(root);
    if(strncmp(host,root,length)||host[length]!='/'||!win_copy(relative,sizeof(relative),host+length+1u)){errno=EACCES;return -1;}
    directory=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(directory<0)return -1;
    part=relative;
    while((next=strchr(part,'/'))!=NULL){
        int child;*next=0;
        child=openat(directory,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);saved=errno;close(directory);
        if(child<0){errno=saved==ENOENT?ENOTDIR:saved;return -1;}
        directory=child;part=next+1;
    }
    if(!*part||!win_copy(leaf,capacity,part)){close(directory);errno=ENAMETOOLONG;return -1;}
    return directory;
}
static uint32_t win_move_error(int code)
{
    if(code==EEXIST)return 183u;
    if(code==EXDEV)return 17u;
    if(code==ENOSYS||code==ENOTSUP)return 50u;
    if(code==ENAMETOOLONG)return 206u;
    return win_commit_error(code);
}
#endif
static uint32_t win_move_file(xxemul_windows *process,const char *source,const char *destination)
{
    char from[2048],to[2048];int directory=0;
    if(!*source||!*destination)return 3u;
    if(!win_guest_path(process,source,from,sizeof(from))||!win_guest_path(process,destination,to,sizeof(to)))return 5u;
    if(win_equal(from,process->program_path)||win_equal(to,process->program_path))return 5u;
#if defined(_WIN32)
    {
        DWORD attributes=GetFileAttributesA(from);
        if(attributes==INVALID_FILE_ATTRIBUTES)return (uint32_t)GetLastError();
        if(attributes&FILE_ATTRIBUTE_REPARSE_POINT)return 5u;
        directory=(attributes&FILE_ATTRIBUTE_DIRECTORY)!=0u;
        if(!win_move_paths_fit(process,from,to,directory))return 206u;
        if(!MoveFileA(from,to))return (uint32_t)GetLastError();
    }
#else
    {
        char from_leaf[2048],to_leaf[2048];struct stat original,target;int from_parent=-1,to_parent=-1,saved;uint32_t error=0u;
        from_parent=win_move_parent(process,from,from_leaf,sizeof(from_leaf));
        if(from_parent<0)return win_move_error(errno);
        to_parent=win_move_parent(process,to,to_leaf,sizeof(to_leaf));
        if(to_parent<0){saved=errno;close(from_parent);return win_move_error(saved);}
        if(fstatat(from_parent,from_leaf,&original,AT_SYMLINK_NOFOLLOW)){error=win_move_error(errno);goto done;}
        if(!S_ISREG(original.st_mode)&&!S_ISDIR(original.st_mode)){error=5u;goto done;}
        directory=S_ISDIR(original.st_mode);
        if(!fstatat(to_parent,to_leaf,&target,AT_SYMLINK_NOFOLLOW)){error=183u;goto done;}
        if(errno!=ENOENT){error=win_move_error(errno);goto done;}
        if(!win_move_paths_fit(process,from,to,directory)){error=206u;goto done;}
#if defined(__linux__) && defined(SYS_renameat2)
        if(syscall(SYS_renameat2,from_parent,from_leaf,to_parent,to_leaf,1u))error=win_move_error(errno);
#elif defined(__APPLE__) && defined(RENAME_EXCL)
        if(renameatx_np(from_parent,from_leaf,to_parent,to_leaf,RENAME_EXCL))error=win_move_error(errno);
#else
        error=50u;
#endif
    done:
        close(to_parent);close(from_parent);
        if(error)return error;
    }
#endif
    win_move_paths_commit(process,from,to,directory);
    return 0u;
}
