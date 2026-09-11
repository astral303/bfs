// Copyright © Tavian Barnes <tavianator@tavianator.com>
// SPDX-License-Identifier: 0BSD

#include "dir.h"

#include "alloc.h"
#include "bfs.h"
#include "bfstd.h"
#include "diag.h"
#include "sanity.h"
#include "stat.h"
#include "trie.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if BFS_USE_GETATTRLISTBULK
#  include <sys/attr.h>
#  include <sys/vnode.h>
#endif

#if BFS_USE_GETDENTS
#  if BFS_HAS_GETDENTS64_SYSCALL
#    include <sys/syscall.h>
#  endif

/** getdents() syscall wrapper. */
static ssize_t bfs_getdents(int fd, void *buf, size_t size) {
	sanitize_uninit(buf, size);

#if BFS_HAS_POSIX_GETDENTS
	int flags = 0;
#  ifdef DT_FORCE_TYPE
	flags |= DT_FORCE_TYPE;
#  endif
	ssize_t ret = posix_getdents(fd, buf, size, flags);
#elif BFS_HAS_GETDENTS
	ssize_t ret = getdents(fd, buf, size);
#elif BFS_HAS_GETDENTS64
	ssize_t ret = getdents64(fd, buf, size);
#elif BFS_HAS_GETDENTS64_SYSCALL
	ssize_t ret = syscall(SYS_getdents64, fd, buf, size);
#else
#  error "No getdents() implementation"
#endif

	if (ret > 0) {
		sanitize_init(buf, ret);
	}

	return ret;
}

#endif // BFS_USE_GETDENTS

/** Directory entry type for bfs_getdents() */
#if !BFS_USE_GETDENTS || BFS_HAS_GETDENTS
typedef struct dirent sys_dirent;
#elif BFS_HAS_POSIX_GETDENTS
typedef struct posix_dent sys_dirent;
#else
typedef struct dirent64 sys_dirent;
#endif

enum bfs_type bfs_mode_to_type(mode_t mode) {
	switch (mode & S_IFMT) {
#ifdef S_IFBLK
	case S_IFBLK:
		return BFS_BLK;
#endif
#ifdef S_IFCHR
	case S_IFCHR:
		return BFS_CHR;
#endif
#ifdef S_IFDIR
	case S_IFDIR:
		return BFS_DIR;
#endif
#ifdef S_IFDOOR
	case S_IFDOOR:
		return BFS_DOOR;
#endif
#ifdef S_IFIFO
	case S_IFIFO:
		return BFS_FIFO;
#endif
#ifdef S_IFLNK
	case S_IFLNK:
		return BFS_LNK;
#endif
#ifdef S_IFPORT
	case S_IFPORT:
		return BFS_PORT;
#endif
#ifdef S_IFREG
	case S_IFREG:
		return BFS_REG;
#endif
#ifdef S_IFSOCK
	case S_IFSOCK:
		return BFS_SOCK;
#endif
#ifdef S_IFWHT
	case S_IFWHT:
		return BFS_WHT;
#endif

	default:
		return BFS_UNKNOWN;
	}
}

/**
 * Private directory flags.
 */
enum {
	/** We've reached the end of the directory. */
	BFS_DIR_EOF   = BFS_DIR_PRIVATE << 0,
	/** This directory is a union mount we need to dedup manually. */
	BFS_DIR_UNION = BFS_DIR_PRIVATE << 1,
};

struct bfs_dir {
	unsigned int flags;

#if BFS_USE_GETDENTS
	int fd;
	unsigned short pos;
	unsigned short size;
#  if __FreeBSD__
	struct trie trie;
#  endif
	alignas(sys_dirent) char buf[];
#elif BFS_USE_GETATTRLISTBULK
	int fd;
	/** Offset of the next unread record in buf. */
	unsigned short pos;
	/** Bytes of valid records in buf. */
	unsigned short size;
	/** readdir() fallback for filesystems without getattrlistbulk() support, else NULL. */
	DIR *dir;
	/** The pending readdir() entry, if any. */
	struct dirent *de;
	/** Storage for bfs_dirent::lstat. */
	struct bfs_stat lstat_buf;
	alignas(uint64_t) char buf[];
#else
	DIR *dir;
	struct dirent *de;
#endif
};

#if BFS_USE_GETDENTS || BFS_USE_GETATTRLISTBULK
#  define DIR_SIZE (64 << 10)
#  define BUF_SIZE (DIR_SIZE - sizeof(struct bfs_dir))
#else
#  define DIR_SIZE sizeof(struct bfs_dir)
#endif

struct bfs_dir *bfs_allocdir(void) {
	return malloc(DIR_SIZE);
}

void bfs_dir_arena(struct arena *arena) {
	arena_init(arena, alignof(struct bfs_dir), DIR_SIZE);
}

#if !BFS_USE_GETDENTS

/** Open the readdir() implementation on an already-open descriptor. */
static int bfs_fdopendir(struct bfs_dir *dir, int fd) {
	dir->dir = fdopendir(fd);
	if (!dir->dir) {
		return -1;
	}
	dir->de = NULL;
	return 0;
}

/** bfs_polldir() implementation backed by readdir(). */
static int bfs_polldir_readdir(struct bfs_dir *dir) {
	if (dir->de) {
		return 1;
	} else if (dir->flags & BFS_DIR_EOF) {
		return 0;
	}

	errno = 0;
	dir->de = readdir(dir->dir);
	if (dir->de) {
		return 1;
	} else if (errno == 0) {
		dir->flags |= BFS_DIR_EOF;
		return 0;
	} else {
		return -1;
	}
}

#endif // !BFS_USE_GETDENTS

#if BFS_USE_GETATTRLISTBULK

/** Attributes requested for every directory entry. */
#define BFS_ATTR_CMN_NAMES (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE)

/** Common attributes required to fill a struct bfs_stat. */
#define BFS_ATTR_CMN_STAT ( \
	ATTR_CMN_DEVID \
	| ATTR_CMN_MODTIME \
	| ATTR_CMN_CHGTIME \
	| ATTR_CMN_ACCTIME \
	| ATTR_CMN_OWNERID \
	| ATTR_CMN_GRPID \
	| ATTR_CMN_ACCESSMASK \
	| ATTR_CMN_FLAGS \
	| ATTR_CMN_FILEID)

/** File attributes required to fill a struct bfs_stat. */
#define BFS_ATTR_FILE_STAT (ATTR_FILE_LINKCOUNT | ATTR_FILE_ALLOCSIZE | ATTR_FILE_DATALENGTH)

/** The attribute request for bfs_opendir() without BFS_DIR_STAT. */
static const struct attrlist bfs_attrlist_names = {
	.bitmapcount = ATTR_BIT_MAP_COUNT,
	.commonattr = BFS_ATTR_CMN_NAMES,
};

/** The attribute request for bfs_opendir() with BFS_DIR_STAT. */
static const struct attrlist bfs_attrlist_stat = {
	.bitmapcount = ATTR_BIT_MAP_COUNT,
	.commonattr = BFS_ATTR_CMN_NAMES | BFS_ATTR_CMN_STAT | ATTR_CMN_CRTIME,
	.fileattr = BFS_ATTR_FILE_STAT,
};

/** Smallest remaining buffer space worth an eager getattrlistbulk() call. */
#define BFS_ATTRBUF_MIN (4 << 10)

/**
 * getattrlistbulk() wrapper.
 *
 * @return
 *         The number of bytes of records read, 0 at EOF, or -1 on failure.
 */
static ssize_t bfs_getattrlistbulk(struct bfs_dir *dir, char *buf, size_t size) {
	struct attrlist attrs = (dir->flags & BFS_DIR_STAT) ? bfs_attrlist_stat : bfs_attrlist_names;

	sanitize_uninit(buf, size);
	int count = getattrlistbulk(dir->fd, &attrs, buf, size, 0);
	if (count <= 0) {
		return count;
	}

	// The syscall returns an entry count; each record starts with its length
	size_t total = 0;
	for (int i = 0; i < count; ++i) {
		char *record = buf + total;
		uint32_t length;
		if (size - total < sizeof(length)) {
			goto malformed;
		}
		sanitize_init(record, sizeof(length));
		memcpy(&length, record, sizeof(length));

		if (length < sizeof(length) + sizeof(attribute_set_t) || length > size - total) {
			goto malformed;
		}
		sanitize_init(record, length);
		total += length;
	}

	return total;

malformed:
	errno = EIO;
	return -1;
}

/** Convert an fsobj_type_t to an S_IFMT value. */
static mode_t bfs_vtype_to_mode(fsobj_type_t vtype) {
	switch ((enum vtype)vtype) {
	case VREG:
		return S_IFREG;
	case VDIR:
		return S_IFDIR;
	case VBLK:
		return S_IFBLK;
	case VCHR:
		return S_IFCHR;
	case VLNK:
		return S_IFLNK;
	case VSOCK:
		return S_IFSOCK;
	case VFIFO:
		return S_IFIFO;
	default:
		return 0;
	}
}

/** A cursor over the attributes of one getattrlistbulk() record. */
struct bfs_attrcur {
	const char *ptr;
	const char *end;
};

/** Read the next attribute, which is only 4-byte aligned, out of a record. */
static bool bfs_attr_take(struct bfs_attrcur *cur, void *dest, size_t size) {
	if ((size_t)(cur->end - cur->ptr) < size) {
		return false;
	}

	memcpy(dest, cur->ptr, size);
	cur->ptr += size;
	return true;
}

/** Read the next attribute if its bit was returned. */
#define BFS_ATTR_TAKE(cur, returned, bit, dest) \
	(!((returned) & (bit)) || bfs_attr_take(cur, dest, sizeof(*(dest))))

/**
 * Fill a struct bfs_stat from the attributes of a regular file, symlink,
 * fifo, or socket.
 *
 * @return
 *         true if every attribute needed by bfs_stat() was returned.
 */
static bool bfs_attrs_to_stat(struct bfs_attrcur *cur, const attribute_set_t *returned, dev_t dev, mode_t ifmt, struct bfs_stat *buf) {
	attrgroup_t cmn = returned->commonattr;
	attrgroup_t file = returned->fileattr;

	if ((cmn & BFS_ATTR_CMN_STAT) != BFS_ATTR_CMN_STAT || (file & BFS_ATTR_FILE_STAT) != BFS_ATTR_FILE_STAT) {
		return false;
	}

	struct timespec crtime, modtime, chgtime, acctime;
	uid_t uid;
	gid_t gid;
	uint32_t accessmask, flags, linkcount;
	uint64_t fileid;
	off_t allocsize, datalength;

	bool ok = BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_CRTIME, &crtime)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_MODTIME, &modtime)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_CHGTIME, &chgtime)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_ACCTIME, &acctime)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_OWNERID, &uid)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_GRPID, &gid)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_ACCESSMASK, &accessmask)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_FLAGS, &flags)
		&& BFS_ATTR_TAKE(cur, cmn, ATTR_CMN_FILEID, &fileid)
		&& BFS_ATTR_TAKE(cur, file, ATTR_FILE_LINKCOUNT, &linkcount)
		&& BFS_ATTR_TAKE(cur, file, ATTR_FILE_ALLOCSIZE, &allocsize)
		&& BFS_ATTR_TAKE(cur, file, ATTR_FILE_DATALENGTH, &datalength);
	if (!ok) {
		return false;
	}

	buf->mask = BFS_STAT_MODE | BFS_STAT_DEV | BFS_STAT_INO | BFS_STAT_NLINK
		| BFS_STAT_GID | BFS_STAT_UID | BFS_STAT_SIZE | BFS_STAT_BLOCKS
		| BFS_STAT_RDEV | BFS_STAT_ATTRS | BFS_STAT_ATIME | BFS_STAT_CTIME
		| BFS_STAT_MTIME | BFS_STAT_MNT_ID;

	buf->mode = (accessmask & ~S_IFMT) | ifmt;
	buf->dev = dev;
	buf->ino = fileid;
	buf->nlink = linkcount;
	buf->gid = gid;
	buf->uid = uid;
	buf->size = datalength;
	buf->blocks = (allocsize + BFS_STAT_BLKSIZE - 1) / BFS_STAT_BLKSIZE;
	buf->rdev = 0;
	// No mount IDs, so use the dev_t as an approximation like bfs_stat_convert()
	buf->mnt_id = dev;
	buf->attrs = flags;
	buf->atime = acctime;
	buf->ctime = chgtime;
	buf->mtime = modtime;

	if (cmn & ATTR_CMN_CRTIME) {
		buf->btime = crtime;
		buf->mask |= BFS_STAT_BTIME;
	}

	return true;
}

/**
 * Parse one getattrlistbulk() record.
 *
 * @return
 *         1 if de was filled, 0 if the entry should be skipped, -1 on a
 *         malformed record.
 */
static int bfs_parse_attrs(struct bfs_dir *dir, const char *record, uint32_t length, struct bfs_dirent *de) {
	struct bfs_attrcur cur = {
		.ptr = record + sizeof(uint32_t),
		.end = record + length,
	};

	attribute_set_t returned;
	if (!bfs_attr_take(&cur, &returned, sizeof(returned))) {
		goto malformed;
	}
	attrgroup_t cmn = returned.commonattr;

	// ATTR_CMN_ERROR precedes every other attribute despite its bit value
	uint32_t error = 0;
	if (!BFS_ATTR_TAKE(&cur, cmn, ATTR_CMN_ERROR, &error)) {
		goto malformed;
	}

	attrreference_t nameref;
	const char *name = cur.ptr;
	if (!(cmn & ATTR_CMN_NAME) || !bfs_attr_take(&cur, &nameref, sizeof(nameref))) {
		goto malformed;
	}
	if (nameref.attr_dataoffset < 0 || nameref.attr_dataoffset > cur.end - name) {
		goto malformed;
	}
	name += nameref.attr_dataoffset;
	if (nameref.attr_length > (size_t)(cur.end - name) || !memchr(name, '\0', nameref.attr_length)) {
		goto malformed;
	}

	if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) {
		return 0;
	}

	if (!de) {
		return 1;
	}

	de->name = name;
	de->type = BFS_UNKNOWN;
	de->lstat = NULL;
	if (error != 0) {
		return 1;
	}

	dev_t dev = 0;
	fsobj_type_t vtype = VNON;
	if (!BFS_ATTR_TAKE(&cur, cmn, ATTR_CMN_DEVID, &dev)
	    || !BFS_ATTR_TAKE(&cur, cmn, ATTR_CMN_OBJTYPE, &vtype)) {
		goto malformed;
	}

	mode_t ifmt = bfs_vtype_to_mode(vtype);
	de->type = bfs_mode_to_type(ifmt);

	// Directories are excluded: their st_nlink is not a returned attribute,
	// and mount points and firmlinks report the underlying directory.
	// Devices are excluded: ATTR_FILE_DEVTYPE differs from st_rdev for devfs
	// cloning devices.
	switch (ifmt) {
	case S_IFREG:
	case S_IFLNK:
	case S_IFIFO:
	case S_IFSOCK:
		break;
	default:
		return 1;
	}
	if (!(dir->flags & BFS_DIR_STAT)) {
		return 1;
	}

	if (bfs_attrs_to_stat(&cur, &returned, dev, ifmt, &dir->lstat_buf)) {
		de->lstat = &dir->lstat_buf;
	}
	return 1;

malformed:
	errno = EIO;
	return -1;
}

/** Fall back to readdir() for a filesystem without getattrlistbulk() support. */
static int bfs_attr_fallback(struct bfs_dir *dir) {
	if (bfs_fdopendir(dir, dir->fd) != 0) {
		return -1;
	}
	return bfs_polldir_readdir(dir);
}

/** bfs_polldir() implementation backed by getattrlistbulk(). */
static int bfs_polldir_attrs(struct bfs_dir *dir) {
	if (dir->pos < dir->size) {
		return 1;
	} else if (dir->flags & BFS_DIR_EOF) {
		return 0;
	}

	char *buf = dir->buf;
	ssize_t size = bfs_getattrlistbulk(dir, buf, BUF_SIZE);
	if (size == 0) {
		dir->flags |= BFS_DIR_EOF;
		return 0;
	} else if (size < 0) {
		// Nothing has been read yet, so mixing in readdir() is well-defined
		bool unread = dir->size == 0;
		if (unread && (errno == ENOTSUP || errno == EINVAL)) {
			return bfs_attr_fallback(dir);
		}
		return -1;
	}

	dir->pos = 0;
	dir->size = size;

	// Like getdents(), EOF is only indicated by a call returning zero.
	// Check that eagerly here to hopefully avoid a syscall in the last bfs_readdir().
	size_t rest = BUF_SIZE - size;
	if (rest >= BFS_ATTRBUF_MIN) {
		size = bfs_getattrlistbulk(dir, buf + size, rest);
		if (size > 0) {
			dir->size += size;
		} else if (size == 0) {
			dir->flags |= BFS_DIR_EOF;
		}
	}

	return 1;
}

/** Read the next getattrlistbulk() record, if there is one. */
static int bfs_readdir_attrs(struct bfs_dir *dir, struct bfs_dirent *de) {
	const char *record = dir->buf + dir->pos;
	uint32_t length;
	memcpy(&length, record, sizeof(length));
	dir->pos += length;

	return bfs_parse_attrs(dir, record, length, de);
}

#endif // BFS_USE_GETATTRLISTBULK

int bfs_opendir(struct bfs_dir *dir, int at_fd, const char *at_path, enum bfs_dir_flags flags) {
	int fd;
	if (at_path) {
		fd = openat(at_fd, at_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
		if (fd < 0) {
			return -1;
		}
	} else if (at_fd >= 0) {
		fd = at_fd;
	} else {
		errno = EBADF;
		return -1;
	}

	dir->flags = flags;

#if BFS_USE_GETDENTS
	dir->fd = fd;
	dir->pos = 0;
	dir->size = 0;

#  if __FreeBSD__ && defined(F_ISUNIONSTACK)
	if (fcntl(fd, F_ISUNIONSTACK) > 0) {
		dir->flags |= BFS_DIR_UNION;
		trie_init(&dir->trie);
	}
#  endif
#elif BFS_USE_GETATTRLISTBULK
	dir->fd = fd;
	dir->pos = 0;
	dir->size = 0;
	dir->dir = NULL;
	dir->de = NULL;
#else
	if (bfs_fdopendir(dir, fd) != 0) {
		if (at_path) {
			close_quietly(fd);
		}
		return -1;
	}
#endif

	return 0;
}

int bfs_dirfd(const struct bfs_dir *dir) {
#if BFS_USE_GETDENTS || BFS_USE_GETATTRLISTBULK
	return dir->fd;
#else
	return dirfd(dir->dir);
#endif
}

int bfs_polldir(struct bfs_dir *dir) {
#if BFS_USE_GETDENTS
	if (dir->pos < dir->size) {
		return 1;
	} else if (dir->flags & BFS_DIR_EOF) {
		return 0;
	}

	char *buf = (char *)(dir + 1);
	ssize_t size = bfs_getdents(dir->fd, buf, BUF_SIZE);
	if (size == 0) {
		dir->flags |= BFS_DIR_EOF;
		return 0;
	} else if (size < 0) {
		return -1;
	}

	dir->pos = 0;
	dir->size = size;

	// Like read(), getdents() doesn't indicate EOF until another call returns zero.
	// Check that eagerly here to hopefully avoid a syscall in the last bfs_readdir().
	size_t rest = BUF_SIZE - size;
	if (rest >= sizeof(sys_dirent)) {
		size = bfs_getdents(dir->fd, buf + size, rest);
		if (size > 0) {
			dir->size += size;
		} else if (size == 0) {
			dir->flags |= BFS_DIR_EOF;
		}
	}

	return 1;
#elif BFS_USE_GETATTRLISTBULK
	if (dir->dir) {
		return bfs_polldir_readdir(dir);
	} else {
		return bfs_polldir_attrs(dir);
	}
#else
	return bfs_polldir_readdir(dir);
#endif
}

/** Take the polled directory entry. */
static const sys_dirent *bfs_getdent(struct bfs_dir *dir) {
#if BFS_USE_GETDENTS
	char *buf = (char *)(dir + 1);
	const sys_dirent *de = (const sys_dirent *)(buf + dir->pos);
	dir->pos += de->d_reclen;
	return de;
#else
	const sys_dirent *de = dir->de;
	dir->de = NULL;
	return de;
#endif
}

/** Skip ".", "..", and deleted/empty dirents. */
static int bfs_skipdent(struct bfs_dir *dir, const sys_dirent *de) {
#if BFS_USE_GETDENTS
#  if __FreeBSD__
	// Union mounts on FreeBSD have to be de-duplicated in userspace
	if (dir->flags & BFS_DIR_UNION) {
		struct trie_leaf *leaf = trie_insert_str(&dir->trie, de->d_name);
		if (!leaf) {
			return -1;
		} else if (leaf->value) {
			return 1;
		} else {
			leaf->value = leaf;
		}
	}

	// NFS mounts on FreeBSD can return empty dirents with inode number 0
	if (de->d_ino == 0) {
		return 1;
	}
#  endif

#  ifdef DT_WHT
	if (de->d_type == DT_WHT && !(dir->flags & BFS_DIR_WHITEOUTS)) {
		return 1;
	}
#  endif
#endif // BFS_USE_GETDENTS

	const char *name = de->d_name;
	return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/** Convert de->d_type to a bfs_type, if it exists. */
static enum bfs_type bfs_d_type(const sys_dirent *de) {
#ifdef DTTOIF
	return bfs_mode_to_type(DTTOIF(de->d_type));
#else
	return BFS_UNKNOWN;
#endif
}

int bfs_readdir(struct bfs_dir *dir, struct bfs_dirent *de) {
	while (true) {
		int ret = bfs_polldir(dir);
		if (ret <= 0) {
			return ret;
		}

#if BFS_USE_GETATTRLISTBULK
		if (!dir->dir) {
			ret = bfs_readdir_attrs(dir, de);
			if (ret == 0) {
				continue;
			}
			return ret;
		}
#endif

		const sys_dirent *sysde = bfs_getdent(dir);
		int skip = bfs_skipdent(dir, sysde);
		if (skip < 0) {
			return skip;
		} else if (skip) {
			continue;
		}

		if (de) {
			de->type = bfs_d_type(sysde);
			de->name = sysde->d_name;
			de->lstat = NULL;
		}

		return 1;
	}
}

static void bfs_destroydir(struct bfs_dir *dir) {
#if BFS_USE_GETDENTS && __FreeBSD__
	if (dir->flags & BFS_DIR_UNION) {
		trie_destroy(&dir->trie);
	}
#endif

	sanitize_uninit(dir, DIR_SIZE);
}

#if !BFS_USE_GETDENTS
/** closedir() wrapper. */
static int bfs_closedir_readdir(struct bfs_dir *dir) {
	int ret = closedir(dir->dir);
	if (ret != 0) {
		bfs_verify(errno != EBADF);
	}
	return ret;
}
#endif

int bfs_closedir(struct bfs_dir *dir) {
#if BFS_USE_GETDENTS
	int ret = xclose(dir->fd);
#elif BFS_USE_GETATTRLISTBULK
	int ret = dir->dir ? bfs_closedir_readdir(dir) : xclose(dir->fd);
#else
	int ret = bfs_closedir_readdir(dir);
#endif

	bfs_destroydir(dir);
	return ret;
}

#if BFS_USE_UNWRAPDIR

#if !BFS_USE_GETDENTS
/** Detach the file descriptor from a DIR, if the platform supports it. */
static int bfs_fdclosedir(DIR *dir) {
#if BFS_HAS_FDCLOSEDIR
#  if __APPLE__ && __has_builtin(__builtin_available)
#    define BFS_FDCLOSEDIR_AVAILABLE  __builtin_available(macos 26.4, ios 26.4, watchos 26.4, tvos 26.4, visionos 26.4, *)
#  else
#    define BFS_FDCLOSEDIR_AVAILABLE true
#  endif
	if (BFS_FDCLOSEDIR_AVAILABLE) {
		return fdclosedir(dir);
	}
#endif

	errno = ENOTSUP;
	return -1;
}
#endif

int bfs_unwrapdir(struct bfs_dir *dir) {
	int ret;
#if BFS_USE_GETDENTS
	ret = dir->fd;
#elif BFS_USE_GETATTRLISTBULK
	if (dir->dir) {
		ret = bfs_fdclosedir(dir->dir);
	} else {
		ret = dir->fd;
	}
#else
	ret = bfs_fdclosedir(dir->dir);
#endif

	if (ret < 0) {
		return -1;
	}

	bfs_destroydir(dir);
	return ret;
}

#endif // BFS_USE_UNWRAPDIR
