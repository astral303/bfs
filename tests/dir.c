// Copyright © Tavian Barnes <tavianator@tavianator.com>
// SPDX-License-Identifier: 0BSD

#include "tests.h"

#include "bfstd.h"
#include "diag.h"
#include "dir.h"
#include "stat.h"
#include "trie.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if BFS_USE_GETATTRLISTBULK

/** Fixture entries, created in this order and removed in reverse. */
static const char *const fixture_names[] = {
	"file",
	"link",
	"symlink",
	"broken",
	"fifo",
	"sock",
	"subdir",
	"ünïcode.txt",
};

/** Create a socket named path in the current directory. */
static int make_socket(const char *name) {
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	if (strlen(name) >= sizeof(addr.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(addr.sun_path, name);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	close_quietly(fd);
	return ret;
}

/** Create the fixture directory under $TMPDIR, chdir()ing into it. */
static char *make_fixture(void) {
	const char *tmpdir = getenv("TMPDIR");
	if (!tmpdir || tmpdir[0] != '/') {
		tmpdir = "/tmp";
	}

	char *path = NULL;
	if (asprintf(&path, "%s/bfs-dir-XXXXXX", tmpdir) < 0) {
		return NULL;
	}
	if (!mkdtemp(path)) {
		free(path);
		return NULL;
	}

	// sockaddr_un::sun_path is short, so create everything relative to the fixture
	int cwd = open(".", O_RDONLY | O_DIRECTORY);
	bool ok = cwd >= 0 && chdir(path) == 0;

	int fd = open("file", O_WRONLY | O_CREAT | O_EXCL, 0644);
	ok = ok && fd >= 0 && write(fd, "hello\n", 6) == 6 && close(fd) == 0;

	ok = ok && link("file", "link") == 0;
	ok = ok && symlink("file", "symlink") == 0;
	ok = ok && symlink("nowhere/at/all", "broken") == 0;
	ok = ok && mkfifo("fifo", 0600) == 0;
	ok = ok && make_socket("sock") == 0;
	ok = ok && mkdir("subdir", 0755) == 0;
	ok = ok && symlink("file", "ünïcode.txt") == 0;

	ok = ok && fchdir(cwd) == 0;
	close_quietly(cwd);

	if (!ok) {
		bfs_ediag("make_fixture()");
	}
	return path;
}

/** Remove the fixture directory. */
static void remove_fixture(char *path) {
	int dfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dfd >= 0) {
		for (size_t i = countof(fixture_names); i-- > 0;) {
			const char *name = fixture_names[i];
			int flags = strcmp(name, "subdir") == 0 ? AT_REMOVEDIR : 0;
			bfs_echeck(unlinkat(dfd, name, flags) == 0, "unlinkat('%s')", name);
		}
		close_quietly(dfd);
	}

	bfs_echeck(rmdir(path) == 0, "rmdir('%s')", path);
	free(path);
}

/** Check two timespecs for equality. */
static bool timespec_eq(const struct timespec *a, const struct timespec *b) {
	return a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec;
}

/**
 * Compare a getattrlistbulk()-derived bfs_stat with bfs_stat(BFS_STAT_NOFOLLOW).
 *
 * @full
 *         True to compare every field; false to compare only the identity
 *         fields that are stable in shared system directories.
 */
static void check_lstat(int dfd, const char *name, const struct bfs_stat *bulk, bool full) {
	struct bfs_stat expected;
	if (bfs_stat(dfd, name, BFS_STAT_NOFOLLOW, &expected) != 0) {
		// The entry may have disappeared in a shared directory
		bfs_check(!full && errno == ENOENT, "bfs_stat('%s'): %s", name, errstr());
		return;
	}

#define CHECK_FIELD(field) \
	bfs_check(bulk->field == expected.field, "'%s': " #field " %ju != %ju", name, (uintmax_t)bulk->field, (uintmax_t)expected.field)

	bfs_check((bulk->mask & expected.mask) == bulk->mask, "'%s': mask %#x has bits missing from %#x", name, bulk->mask, expected.mask);
	CHECK_FIELD(mode);
	CHECK_FIELD(dev);
	CHECK_FIELD(ino);
	CHECK_FIELD(rdev);

	if (!full) {
		return;
	}

	CHECK_FIELD(nlink);
	CHECK_FIELD(uid);
	CHECK_FIELD(gid);
	CHECK_FIELD(size);
	CHECK_FIELD(blocks);
	CHECK_FIELD(attrs);
	CHECK_FIELD(mnt_id);
#undef CHECK_FIELD

#define CHECK_TIME(field, bit) \
	bfs_check(!(bulk->mask & bit) || timespec_eq(&bulk->field, &expected.field), "'%s': " #field " differs", name)

	CHECK_TIME(atime, BFS_STAT_ATIME);
	CHECK_TIME(btime, BFS_STAT_BTIME);
	CHECK_TIME(ctime, BFS_STAT_CTIME);
	CHECK_TIME(mtime, BFS_STAT_MTIME);
#undef CHECK_TIME
}

/** Collect the names in a directory with libc readdir(). */
static size_t readdir_names(const char *path, struct trie *names) {
	size_t count = 0;

	DIR *dir = opendir(path);
	if (!bfs_echeck(dir, "opendir('%s')", path)) {
		return 0;
	}

	struct dirent *de;
	while ((de = readdir(dir))) {
		const char *name = de->d_name;
		if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) {
			continue;
		}
		bfs_everify(trie_insert_str(names, name), "trie_insert_str()");
		++count;
	}

	closedir(dir);
	return count;
}

/** Checks that hold for every entry of any directory. */
static void check_dirent(const struct bfs_dirent *de, enum bfs_dir_flags flags) {
	const char *name = de->name;

	bfs_check(strcmp(name, ".") != 0 && strcmp(name, "..") != 0, "'%s': dot entry returned", name);

	if (!(flags & BFS_DIR_STAT)) {
		bfs_check(!de->lstat, "'%s': lstat filled without BFS_DIR_STAT", name);
	}
	if (de->type == BFS_DIR) {
		bfs_check(!de->lstat, "'%s': lstat filled for a directory", name);
	}
	if (de->lstat) {
		enum bfs_type lstat_type = bfs_mode_to_type(de->lstat->mode);
		bfs_check(lstat_type == de->type, "'%s': type %d != lstat type %d", name, (int)de->type, (int)lstat_type);
	}
}

/** Checks that rely on the fixture directory's known contents. */
static void check_fixture_dirent(const struct bfs_dirent *de, enum bfs_dir_flags flags, struct trie *names) {
	const char *name = de->name;

	bfs_check(trie_find_str(names, name), "'%s': not found by readdir()", name);

	if (de->type != BFS_DIR) {
		bfs_check(de->type != BFS_UNKNOWN, "'%s': unknown type", name);
		bfs_check(!(flags & BFS_DIR_STAT) || de->lstat, "'%s': lstat missing", name);
	}
}

/**
 * Read a directory with bfs_readdir() and compare it with readdir()/lstat().
 *
 * @full
 *         True for the fixture directory; its contents are known.
 * @return
 *         The number of entries with stat info.
 */
static size_t check_readdir(const char *path, enum bfs_dir_flags flags, bool full) {
	struct trie names;
	trie_init(&names);
	size_t expected = readdir_names(path, &names);

	struct bfs_dir *dir = bfs_allocdir();
	bfs_everify(dir, "bfs_allocdir()");
	bfs_everify(bfs_opendir(dir, AT_FDCWD, path, flags) == 0, "bfs_opendir('%s')", path);
	int dfd = bfs_dirfd(dir);

	size_t count = 0;
	size_t with_lstat = 0;
	struct bfs_dirent de;
	int ret;
	while ((ret = bfs_readdir(dir, &de)) > 0) {
		++count;
		check_dirent(&de, flags);
		if (full) {
			check_fixture_dirent(&de, flags, &names);
		}

		if (de.lstat) {
			++with_lstat;
			check_lstat(dfd, de.name, de.lstat, full);
		}
	}
	bfs_echeck(ret == 0, "bfs_readdir('%s')", path);

	if (full) {
		bfs_check(count == expected, "'%s': %zu entries != %zu from readdir()", path, count, expected);
	}

	bfs_echeck(bfs_closedir(dir) == 0, "bfs_closedir('%s')", path);
	free(dir);
	trie_destroy(&names);
	return with_lstat;
}

/** bfs_readdir(dir, NULL) and bfs_unwrapdir() checks. */
static void check_peek_unwrap(const char *path) {
	struct bfs_dir *dir = bfs_allocdir();
	bfs_everify(dir, "bfs_allocdir()");
	bfs_everify(bfs_opendir(dir, AT_FDCWD, path, BFS_DIR_STAT) == 0, "bfs_opendir('%s')", path);

	bfs_echeck(bfs_readdir(dir, NULL) == 1, "bfs_readdir(NULL)");

	int fd = bfs_unwrapdir(dir);
	bfs_echeck(fd >= 0, "bfs_unwrapdir()");
	free(dir);

	int child = openat(fd, "file", O_RDONLY);
	bfs_echeck(child >= 0, "openat(unwrapped fd, 'file')");
	close_quietly(child);
	close_quietly(fd);
}

void check_dir(void) {
	char *fixture = make_fixture();
	bfs_everify(fixture, "make_fixture()");

	size_t with_lstat = check_readdir(fixture, BFS_DIR_STAT, true);
	bfs_check(with_lstat == countof(fixture_names) - 1, "%zu fixture entries with lstat, expected %zu", with_lstat, countof(fixture_names) - 1);
	check_readdir(fixture, 0, true);
	check_peek_unwrap(fixture);

	remove_fixture(fixture);

	// Shared directories: firmlinks, volume groups, devices, mount points
	check_readdir("/", BFS_DIR_STAT, false);
	check_readdir("/System/Volumes", BFS_DIR_STAT, false);
	check_readdir("/dev", BFS_DIR_STAT, false);
	check_readdir("/Volumes", BFS_DIR_STAT, false);
	check_readdir("/usr/bin", BFS_DIR_STAT, false);
}

#else // !BFS_USE_GETATTRLISTBULK

void check_dir(void) {
}

#endif
