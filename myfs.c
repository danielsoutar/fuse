/*
 ############################################################################################################################################################################################
 ######################################################################          ______   ______    _____   _          ######################################################################
 ######################################################################         |  ____| |  ____|  / ____| | |         ######################################################################
 ######################################################################         | |__    | |__    | (___   | |         ######################################################################
 ######################################################################         |  __|   |  __|    \___ \  | |         ######################################################################
 ######################################################################         | |      | |       ____) | |_|         ######################################################################
 ######################################################################         |_|      |_|      |_____/  (_)*        ######################################################################
 ######################################################################                                                ######################################################################
 ############################################################################################################################################################################################
	*FFS: Fast File System
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "myfs.h"

#define ptr_add(ptr, x) ((void*)(ptr) + (x))
#define ptr_sub(ptr, x) ((void*)(ptr) - (x))

#define SLASH "/"
#define DIRENTHASHSIZE 3

// Let's cache the root fcb and dirent data structure in memory.
char root_path[2] = "/\0";
fcb root_fcb;
Dirent * root_table[DIRENTHASHSIZE];
unqlite_int64 root_object_size_value = sizeof(fcb);

Dirent * dirent_hash_table[DIRENTHASHSIZE];

// This is the pointer to the database we will use to store all our files
unqlite *pDb;
uuid_t zero_uuid;

// The functions which follow are handler functions for various things a filesystem needs to do:
// reading, getting attributes, truncating, etc. They will be called by FUSE whenever it needs
// your filesystem to do something, so this is where functionality goes.

// Auxiliary methods

// Creating a hash table structure for use in directories. I fully acknowledge the following code as borrowing/at least inspired from Kernighan & Ritchie's phenomenal C programming book.

unsigned int hash(char *name) {
    unsigned int hashval;

    for(hashval = 0; *name != '\0'; name++)
        hashval = *name + 31 * hashval;
    return hashval % DIRENTHASHSIZE;	// What a beautifully concise hash function. Those guys knew how to write good code.
}

Dirent * lookup(char *name) {
    Dirent *item;

    for(item = dirent_hash_table[hash(name)]; item != NULL; item = item->next)
        if(strcmp(name, item->name) == 0)
            return item;
    return NULL;
}

int install(char *name, uuid_t data) {
    Dirent *item;
    unsigned int hashval;

    if((item = lookup(name)) == NULL) {
        item = (Dirent *) malloc(sizeof(Dirent));
        if(item == NULL)
            return -1;

        for(int i = 0; i < MAX_PATH_SIZE; i++)
            item->name[i] = name[i];

        hashval = hash(name);
        item->next = dirent_hash_table[hashval];
        dirent_hash_table[hashval] = item;
    }
    else  // Item in table, so fail. No sensible reason to update the name or the id.
        return -1;
    return 0;
}

void uninstall(char *name, uuid_t data) {
    Dirent *item, *temp;
    unsigned int hashval;

    if((item = lookup(name)) != NULL) {
        hashval = hash(name);
        temp = dirent_hash_table[hashval];
        //item is first on list, make first of this list the next
        if(temp->data == data)
            dirent_hash_table[hashval] = temp->next;
        //item is somewhere in list, make its previous node point to item's next
        for( ; temp != NULL; temp = temp->next)
            if(temp->next->data == data)
                temp->next = item->next;
        //item removed, now free.
        free(item);
    }
    else
        return; // Nothing to delete
}


// Get file and directory attributes (meta-data).
// Read 'man 2 stat' and 'man 2 chmod'.
static int myfs_getattr(const char *path, struct stat *stbuf) {
    write_log("myfs_getattr(path=\"%s\", statbuf=0x%08x)\n", path, stbuf);

    // Clear memory for the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Check if root, fill buffer with cached values if so
    if(strcmp(path, "/") == 0) {
        stbuf->st_mode = root_fcb.mode;
        stbuf->st_nlink = 2;				// Not going to be fancy with hard links to start with - recognise that root needs 2 since '.' and '..' refer to same directory.
        stbuf->st_uid = root_fcb.uid;
        stbuf->st_gid = root_fcb.gid;
        stbuf->st_mtime = root_fcb.mtime;
        stbuf->st_ctime = root_fcb.ctime;
        stbuf->st_atime = root_fcb.atime;
        stbuf->st_size = root_fcb.size;
    }
    else {
        // Not the root, so get the directory contents of root and work our way down to the requested file, fail with ENOENT if we can't.
        // We'll start off by restricting to just the root directory.

        // The root directory contents, containing a sequence of Dirent objects which contain the mapping from path names to uuids
        
    	char *token, *copy;

    	strcpy(copy, path);

    	while((token = strtok(copy, SLASH)) != NULL) {
    		write_log("token: %s\n", token);
    	}

        if (strcmp(path, root_path) == 0) {
            stbuf->st_mode = root_fcb.mode;
            stbuf->st_nlink = 1;				//by default I'm just going to leave out the ability to make hard links and always set st_nlink to 1.
            stbuf->st_mtime = root_fcb.mtime;
            stbuf->st_ctime = root_fcb.ctime;
            stbuf->st_size = root_fcb.size;
            stbuf->st_uid = root_fcb.uid;
            stbuf->st_gid = root_fcb.gid;
        }
        else {
            write_log("myfs_getattr - ENOENT");
            return -ENOENT;
        }
    }

    return 0;
}

// Read a directory.
// Read 'man 2 readdir'.
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {

    (void) offset;  // This prevents compiler warnings
	(void) fi;

	write_log("write_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n", path, buf, filler, offset, fi);
	
	// This implementation supports only a root directory so return an error if the path is not '/'.
	if (strcmp(path, root_path) != 0) {
		write_log("myfs_readdir - ENOENT");
		return -ENOENT;
	}

    // We always output . and .. first, by convention. See documentation for more info on filler()
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

    // The root FCB is in memory, so we simply read the name of the file from the path variable inside it
	char *pathP = (char*)&(root_path);

	if(*pathP != '\0') {
		// drop the leading '/';
		pathP++;
		filler(buf, pathP, NULL, 0);
	}

    // Only one file, so nothing else to do
	
	return 0;
}

// Read a file.
// Read 'man 2 read'.
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	size_t len;
	(void) fi;
	
	write_log("myfs_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n", path, buf, size, offset, fi);
	
	if(strcmp(path, root_path) != 0) {
		write_log("myfs_read - ENOENT");
		return -ENOENT;
	}
	
	len = root_fcb.size;
	
	uint8_t data_block[MY_MAX_FILE_SIZE];
	
	memset(&data_block, 0, MY_MAX_FILE_SIZE);
	uuid_t *data_id = &(root_fcb.data);
	// Is there a data block?
	if(uuid_compare(zero_uuid, *data_id) != 0) {
		unqlite_int64 num_bytes;  //Data length.
		int rc = unqlite_kv_fetch(pDb, data_id, KEY_SIZE, NULL, &num_bytes);
		
		if(rc != UNQLITE_OK)
		  error_handler(rc);

		if(num_bytes != MY_MAX_FILE_SIZE) {
			write_log("myfs_read - EIO");
			return -EIO;
		}
	
		// Fetch the fcb the root data block from the store.
		unqlite_kv_fetch(pDb, data_id, KEY_SIZE, &data_block, &num_bytes);
	}
	
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, &data_block + offset, size);
	} else
		size = 0;

	return size;
}

// This file system only supports one file. Create should fail if a file has been created. Path must be '/<something>'.
// Read 'man 2 creat'.
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi){   
    write_log("myfs_create(path=\"%s\", mode=0%03o, fi=0x%08x)\n", path, mode, fi);
	    
    if(root_path[0] != '\0') {
		write_log("myfs_create - ENOSPC");
		return -ENOSPC;
	}
		
	int pathlen = strlen(path);

	if(pathlen >= MAX_PATH_SIZE) {
		write_log("myfs_create - ENAMETOOLONG");
		return -ENAMETOOLONG;
	}

	sprintf(root_path, path);
	struct fuse_context *context = fuse_get_context();
	root_fcb.uid = context->uid;
	root_fcb.gid = context->gid;
	root_fcb.mode = mode|S_IFREG;
	
	int rc = unqlite_kv_store(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, sizeof(fcb));

	if(rc != UNQLITE_OK) {
		write_log("myfs_create - EIO");
		return -EIO;
	}
    
    return 0;
}

// Set update the times (actime, modtime) for a file. This FS only supports modtime.
// Read 'man 2 utime'.
static int myfs_utime(const char *path, struct utimbuf *ubuf){
    write_log("myfs_utime(path=\"%s\", ubuf=0x%08x)\n", path, ubuf);
    
	if(strcmp(path, root_path) != 0) {
		write_log("myfs_utime - ENOENT");
		return -ENOENT;
	}

	root_fcb.mtime = ubuf->modtime;
	
	// Write the fcb to the store.
    int rc = unqlite_kv_store(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, sizeof(fcb));

	if(rc != UNQLITE_OK) {
		write_log("myfs_write - EIO");
		return -EIO;
	}
    
    return 0;
}

// Write to a file.
// Read 'man 2 write'
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){   
    write_log("myfs_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n", path, buf, size, offset, fi);
    
	if(strcmp(path, root_path) != 0) {
		write_log("myfs_write - ENOENT");
		return -ENOENT;
    }
	
	if(size >= MY_MAX_FILE_SIZE) {
		write_log("myfs_write - EFBIG");
		return -EFBIG;
	}

	uint8_t data_block[MY_MAX_FILE_SIZE];
	
	memset(&data_block, 0, MY_MAX_FILE_SIZE);
	uuid_t *data_id = &(root_fcb.data);
	// Is there a data block?
	if(uuid_compare(zero_uuid, *data_id) == 0)
		uuid_generate(root_fcb.data); // Generate a UUID for the data block. We'll write the block itself later.
	else {
		// First we will check the size of the obejct in the store to ensure that we won't overflow the buffer.
		unqlite_int64 num_bytes;  // Data length.
		int rc = unqlite_kv_fetch(pDb, data_id, KEY_SIZE, NULL, &num_bytes);

		if(rc != UNQLITE_OK || num_bytes != MY_MAX_FILE_SIZE) {
			write_log("myfs_write - EIO");
			return -EIO;
		}
	
		// Fetch the data block from the store. 
		unqlite_kv_fetch(pDb, data_id, KEY_SIZE, &data_block, &num_bytes);
		// Error handling?
	}
	
	// Write the data in-memory.
    int written = snprintf(data_block, MY_MAX_FILE_SIZE, buf);
	
	// Write the data block to the store.
	int rc = unqlite_kv_store(pDb, data_id, KEY_SIZE, &data_block, MY_MAX_FILE_SIZE);

	if(rc != UNQLITE_OK) {
		write_log("myfs_write - EIO");
		return -EIO;
	}
	
	// Update the fcb in-memory.
	root_fcb.size = written;
	time_t now = time(NULL);
	root_fcb.mtime = now;
	root_fcb.ctime = now;
	
	// Write the fcb to the store.
    rc = unqlite_kv_store(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, sizeof(fcb));

	if(rc != UNQLITE_OK) {
		write_log("myfs_write - EIO");
		return -EIO;
	}
	
    return written;
}

// Set the size of a file.
// Read 'man 2 truncate'.
int myfs_truncate(const char *path, off_t newsize){    
    write_log("myfs_truncate(path=\"%s\", newsize=%lld)\n", path, newsize);
    
    // Check that the size is acceptable
	if(newsize >= MY_MAX_FILE_SIZE) {
		write_log("myfs_truncate - EFBIG");
		return -EFBIG;
	}
	
    // Update the FCB in-memory
	root_fcb.size = newsize;
	
	// Write the fcb to the store.
    int rc = unqlite_kv_store(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, sizeof(fcb));

	if(rc != UNQLITE_OK) {
		write_log("myfs_write - EIO");
		return -EIO;
	}
    
	return 0;
}

// Set permissions.
// Read 'man 2 chmod'.
int myfs_chmod(const char *path, mode_t mode){
    write_log("myfs_chmod(fpath=\"%s\", mode=0%03o)\n", path, mode);
    
    return 0;
}

// Set ownership.
// Read 'man 2 chown'.
int myfs_chown(const char *path, uid_t uid, gid_t gid){   
    write_log("myfs_chown(path=\"%s\", uid=%d, gid=%d)\n", path, uid, gid);
   
    return 0;
}

// Create a directory.
// Read 'man 2 mkdir'.
int myfs_mkdir(const char *path, mode_t mode){
	write_log("myfs_mkdir: %s\n", path);	
	
    return 0;
}

// Delete a file.
// Read 'man 2 unlink'.
int myfs_unlink(const char *path){
	write_log("myfs_unlink: %s\n",path);	
	
    return 0;
}

// Delete a directory.
// Read 'man 2 rmdir'.
int myfs_rmdir(const char *path){
    write_log("myfs_rmdir: %s\n",path);	
	
    return 0;
}

// OPTIONAL - included as an example
// Flush any cached data.
int myfs_flush(const char *path, struct fuse_file_info *fi){
    int retstat = 0;
    
    write_log("myfs_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
	
    return retstat;
}

// OPTIONAL - included as an example
// Release the file. There will be one call to release for each call to open.
int myfs_release(const char *path, struct fuse_file_info *fi){
    int retstat = 0;
    
    write_log("myfs_release(path=\"%s\", fi=0x%08x)\n", path, fi);
    
    return retstat;
}

// OPTIONAL - included as an example
// Open a file. Open should check if the operation is permitted for the given flags (fi->flags).
// Read 'man 2 open'.
static int myfs_open(const char *path, struct fuse_file_info *fi){
	if (strcmp(path, root_path) != 0)
		return -ENOENT;
		
	write_log("myfs_open(path\"%s\", fi=0x%08x)\n", path, fi);
	
	//return -EACCES if the access is not permitted.

	return 0;
}

// This struct contains pointers to all the functions defined above
// It is used to pass the function pointers to fuse
// fuse will then execute the methods as required
static struct fuse_operations myfs_oper = {
    .getattr	= myfs_getattr,
    .readdir	= myfs_readdir,
    .open	= myfs_open,
    .read	= myfs_read,
    .create	= myfs_create,
    .utime 	= myfs_utime,
    .write	= myfs_write,
    .truncate	= myfs_truncate,
    .flush	= myfs_flush,
    .release	= myfs_release,
};

// Initialise the in-memory data structures from the store. If the root object (from the store) is empty then create a root fcb (directory)
// and write it to the store. Note that this code is executed outide of fuse. If there is a failure then we have failed to initialise the
// file system so exit with an error code.
void init_fs() {
    int rc;
    printf("init_fs\n");
    //Initialise the store.

    uuid_clear(zero_uuid);

    // Open the database.
    rc = unqlite_open(&pDb, DATABASE_NAME, UNQLITE_OPEN_CREATE);
    if(rc != UNQLITE_OK)
        error_handler(rc);

    unqlite_int64 num_bytes;  // Data length

    // Try to fetch the root element
    // The last parameter is a pointer to a variable which will hold the number of bytes actually read
    rc = unqlite_kv_fetch(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, &num_bytes);

    // if it doesn't exist, we need to create one and put it into the database. This will be the root
    // directory of our filesystem i.e. "/"
    if(rc == UNQLITE_NOTFOUND) {

        printf("init_store: root object was not found\n");

        // clear everything in root_fcb
        memset(&root_fcb, 0, sizeof(fcb));

        // Sensible initialisation for the root FCB
        //See 'man 2 stat' and 'man 2 chmod'.
        root_fcb.mode |= S_IFDIR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH;
        root_fcb.mtime = time(0);
        root_fcb.ctime = time(0);
        root_fcb.atime = time(0);
        root_fcb.uid = getuid();
        root_fcb.gid = getgid();

        // We have to create a uuid for the root fcb to contain data - the ROOT_OBJECT_KEY is only to get the root fcb to kick off the process.
        uuid_generate(root_fcb.data);

        // Create a data block and some Dirents.
        uint8_t data_block[MY_MAX_FILE_SIZE];
        Dirent current, parent;

        // Set strings for root Dirents
        for(int i = 0; root_path[i] != '\0'; i++) {
        	current.name[i] = root_path[i];
        	parent.name[i] = root_path[i];
        }

        // Set these Dirents to contain the same id as the root
        memcpy(current.data, root_fcb.data, sizeof(uuid_t));
        memcpy(parent.data, root_fcb.data, sizeof(uuid_t));

        // Write these Dirents into the data block
        memcpy(data_block, &current, sizeof(Dirent));        
        memcpy(ptr_add(data_block, sizeof(Dirent)), &parent, sizeof(Dirent));

        // Write the root data block
        printf("init_fs: writing root dirents\n");
        rc = unqlite_kv_store(pDb, &(root_fcb.data), KEY_SIZE, &data_block, sizeof(data_block));

        if(rc != UNQLITE_OK)
            error_handler(rc);

        // Write the root FCB
        printf("init_fs: writing root fcb\n");
        rc = unqlite_kv_store(pDb, ROOT_OBJECT_KEY, ROOT_OBJECT_KEY_SIZE, &root_fcb, sizeof(fcb));

        if(rc != UNQLITE_OK)
            error_handler(rc);

        Dirent* ptr = (Dirent *) data_block;
        Dirent* ptr2 = (Dirent *) data_block + 1;

        printf("Testing some variables before we continue ... \n");
        printf("Curr: \nName: %s\nid is non-zero: %d\nid is equal to root id: %d\n", ptr->name, uuid_compare(zero_uuid, ptr->data) != 0, uuid_compare(root_fcb.data, ptr->data) == 0);
        printf("Pare: \nName: %s\nid is non-zero: %d\nid is equal to root id: %d\n", ptr2->name, uuid_compare(zero_uuid, ptr2->data) != 0, uuid_compare(root_fcb.data, ptr2->data) == 0);
        
    }
    else {
        if(rc == UNQLITE_OK)
            printf("init_store: root object was found\n");
        if(num_bytes != sizeof(fcb)) {
            printf("Data object has unexpected size. Doing nothing.\n");
            exit(-1);
        }
    }
}

void shutdown_fs() {
    unqlite_close(pDb);
}

int main(int argc, char *argv[]) {
    int fuserc;
    struct myfs_state *myfs_internal_state;

    //Setup the log file and store the FILE* in the private data object for the file system.
    myfs_internal_state = malloc(sizeof(struct myfs_state));
    myfs_internal_state->logfile = init_log_file();

    //Initialise the file system. This is being done outside of fuse for ease of debugging.
    init_fs();

    // Now pass our function pointers over to FUSE, so they can be called whenever someone
    // tries to interact with our filesystem. The internal state contains a file handle
    // for the logging mechanism
    fuserc = fuse_main(argc, argv, &myfs_oper, myfs_internal_state);

    //Shutdown the file system.
    shutdown_fs();
    return fuserc;
}
