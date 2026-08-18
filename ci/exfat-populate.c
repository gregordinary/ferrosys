/*
 * exfat-populate — put a tree into an exFAT volume, without a mount.
 *
 * The exFAT family's foreign-image gate needs a volume this crate did not write, with
 * a tree in it: an image the reader has never seen the writer's side of. `exfatprogs`
 * formats and checks, and nothing in it fills. There is no mtools for this family.
 *
 * relan/exfat's `libexfat` is the second complete implementation of the format, and it
 * is a library over a plain file — the FUSE binary in that project is an adapter on top
 * of it, not the thing itself. So this program is the command line that library does not
 * ship: it opens an image file, makes directories and files through the library's own
 * API, and closes it. Every on-disk decision — where clusters go, how a directory entry
 * set is laid out, what its checksums and name hashes are, whether a stream declares
 * `NoFatChain` — belongs to libexfat, exactly as mtools makes them for a FAT image.
 *
 * What that buys over mounting the volume: no `/dev/fuse`, no `fusermount3`, no loop
 * device, no kernel, and no root. The program runs wherever a C compiler does, which is
 * every runner this project has, and needs nothing added to a container.
 *
 * Licensing: the binary this builds links `libexfat`, which is GPL-2.0-or-later, so the
 * binary is under those terms. It is built locally by `ci/build-exfat-populate.sh`, used
 * only by the test suite, and is not part of the crate, its dependency graph, or anything
 * published from this repository.
 *
 * Usage:
 *   exfat-populate --version
 *   exfat-populate IMAGE SCRIPT     (SCRIPT of "-" reads standard input)
 *
 * The script is one command per line. Blank lines and lines whose first non-blank
 * character is `#` are ignored. Fields are separated by runs of spaces and tabs, so no
 * path a script names may contain either.
 *
 *   mkdir PATH          create a directory
 *   write PATH SIZE SEED
 *                       create a file of SIZE bytes, filled with the pattern below
 *   grow PATH SIZE      extend an existing file to SIZE bytes without writing them, so
 *                       its ValidDataLength stays behind its DataLength
 *   unlink PATH         remove a file
 *   label TEXT          set the volume label to the rest of the line
 *
 * `write`'s pattern is a little-endian 32-bit counter: the four bytes at offset 4*j are
 * `j + SEED`, and a trailing partial word is truncated. A reader that lands at the wrong
 * offset therefore reads a word that names the offset it should have been at, which a
 * constant fill cannot show. The gate that checks the file computes the same pattern; the
 * two agreeing is the assertion.
 */

/*
 * Before any system header. libexfat's generated `config.h` defines `_XOPEN_SOURCE` and
 * `_DEFAULT_SOURCE`, and glibc's feature-test macros are read at the first inclusion of
 * anything from it — so a `stdio.h` above this line defines them first and this one
 * redefines them.
 */
#include "exfat.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The relan/exfat release `ci/build-exfat-populate.sh` pins. That script passes it in, so
   the version this program reports is the library it was actually linked against rather
   than a second copy of the pin that could drift from the first. */
#ifndef EXFAT_POPULATE_LIBEXFAT_VERSION
#error "define EXFAT_POPULATE_LIBEXFAT_VERSION to the pinned relan/exfat release"
#endif

/* One chunk of the generated pattern, so a file of any size costs a fixed amount of
   memory. A multiple of four, so a chunk boundary never splits a counter word. */
#define CHUNK 65536

static struct exfat ef;

static void fail(const char *what, int rc)
{
	/* libexfat returns a negated errno, and its own diagnostics have already gone to
	   stderr. Naming both the operation and the code is what makes a failing gate
	   readable without rebuilding this program. */
	fprintf(stderr, "exfat-populate: %s: %s (%d)\n", what, strerror(-rc), rc);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "usage: exfat-populate IMAGE SCRIPT | exfat-populate --version\n");
	exit(2);
}

/* Create `path` and fill it with `size` bytes of the counter pattern. */
static void cmd_write(const char *path, uint64_t size, uint32_t seed)
{
	struct exfat_node *node;
	unsigned char chunk[CHUNK];
	uint64_t offset = 0;
	int rc;

	rc = exfat_mknod(&ef, path);
	if (rc != 0)
		fail(path, rc);
	rc = exfat_lookup(&ef, &node, path);
	if (rc != 0)
		fail(path, rc);

	while (offset < size) {
		size_t want = (size - offset) < CHUNK ? (size_t)(size - offset) : CHUNK;
		ssize_t wrote;
		size_t i;

		for (i = 0; i < want; i++) {
			/* The word this byte belongs to, and which of its four bytes it
			   is. Written per byte rather than per word so that a size that
			   is not a multiple of four truncates the last word rather than
			   overrunning the chunk. */
			uint32_t word = (uint32_t)((offset + i) / 4) + seed;
			chunk[i] = (unsigned char)(word >> (8 * ((offset + i) % 4)));
		}
		wrote = exfat_generic_pwrite(&ef, node, chunk, want, (off_t)offset);
		if (wrote < 0)
			fail(path, (int)wrote);
		if ((size_t)wrote != want) {
			fprintf(stderr, "exfat-populate: %s: short write %zd of %zu\n",
					path, wrote, want);
			exit(1);
		}
		offset += want;
	}

	/* The node carries its own metadata until it is flushed, and nothing else will
	   flush it: this program has no close(2) for the library to hang that on. */
	rc = exfat_flush_node(&ef, node);
	if (rc != 0)
		fail(path, rc);
	exfat_put_node(&ef, node);
}

/* Extend `path` to `size` without writing the new bytes. */
static void cmd_grow(const char *path, uint64_t size)
{
	struct exfat_node *node;
	int rc;

	rc = exfat_lookup(&ef, &node, path);
	if (rc != 0)
		fail(path, rc);
	/* `erase` false is the whole point: the clusters are allocated and the file's
	   length grows, and the bytes past what was written stay undefined — which is the
	   `ValidDataLength` below `DataLength` case a reader has to answer for and a
	   format-time writer never produces. */
	rc = exfat_truncate(&ef, node, size, false);
	if (rc != 0)
		fail(path, rc);
	rc = exfat_flush_node(&ef, node);
	if (rc != 0)
		fail(path, rc);
	exfat_put_node(&ef, node);
}

static void cmd_unlink(const char *path)
{
	struct exfat_node *node;
	int rc;

	rc = exfat_lookup(&ef, &node, path);
	if (rc != 0)
		fail(path, rc);
	rc = exfat_unlink(&ef, node);
	exfat_put_node(&ef, node);
	if (rc != 0)
		fail(path, rc);
	/* The library's own order: the reference is dropped first, and the cleanup then
	   releases the clusters of a node nothing holds. */
	rc = exfat_cleanup_node(&ef, node);
	if (rc != 0)
		fail(path, rc);
}

/* Split `line` at runs of spaces and tabs, in place. Returns how many fields there were,
   which may exceed `max` — a caller that cares refuses the line. */
static size_t split(char *line, char **field, size_t max)
{
	size_t n = 0;
	char *p = line;

	while (*p != '\0') {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0')
			break;
		if (n < max)
			field[n] = p;
		n++;
		while (*p != '\0' && *p != ' ' && *p != '\t')
			p++;
		if (*p != '\0')
			*p++ = '\0';
	}
	return n;
}

static uint64_t number(const char *text, const char *what, unsigned long lineno)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno != 0 || *end != '\0' || end == text) {
		fprintf(stderr, "exfat-populate: line %lu: %s is not a number: %s\n",
				lineno, what, text);
		exit(2);
	}
	return (uint64_t)value;
}

/* Everything after the first field of `raw`, verbatim. Only `label` wants this, and only
   because a volume label may contain spaces — reading it back out of the untouched line
   is what keeps the text exactly what the script wrote, where reassembling the fields
   split() separated would normalize a tab into a space. */
static const char *rest_of_line(const char *raw)
{
	while (*raw == ' ' || *raw == '\t')
		raw++;
	while (*raw != '\0' && *raw != ' ' && *raw != '\t')
		raw++;
	while (*raw == ' ' || *raw == '\t')
		raw++;
	return raw;
}

static void run(FILE *script)
{
	char line[4096];
	unsigned long lineno = 0;

	while (fgets(line, sizeof line, script) != NULL) {
		char *field[4];
		size_t length, fields;
		char *raw;

		lineno++;
		length = strlen(line);
		if (length > 0 && line[length - 1] == '\n')
			line[--length] = '\0';
		else if (length + 1 == sizeof line) {
			fprintf(stderr, "exfat-populate: line %lu is too long\n", lineno);
			exit(2);
		}

		raw = strdup(line);
		if (raw == NULL) {
			fprintf(stderr, "exfat-populate: out of memory\n");
			exit(1);
		}

		fields = split(line, field, sizeof field / sizeof field[0]);
		if (fields == 0 || field[0][0] == '#') {
			free(raw);
			continue;
		}

		if (strcmp(field[0], "mkdir") == 0 && fields == 2) {
			int rc = exfat_mkdir(&ef, field[1]);
			if (rc != 0)
				fail(field[1], rc);
		} else if (strcmp(field[0], "write") == 0 && fields == 4) {
			cmd_write(field[1], number(field[2], "size", lineno),
					(uint32_t)number(field[3], "seed", lineno));
		} else if (strcmp(field[0], "grow") == 0 && fields == 3) {
			cmd_grow(field[1], number(field[2], "size", lineno));
		} else if (strcmp(field[0], "unlink") == 0 && fields == 2) {
			cmd_unlink(field[1]);
		} else if (strcmp(field[0], "label") == 0 && fields >= 2) {
			int rc = exfat_set_label(&ef, rest_of_line(raw));
			if (rc != 0)
				fail("label", rc);
		} else {
			fprintf(stderr, "exfat-populate: line %lu: %s\n", lineno, raw);
			fprintf(stderr, "exfat-populate: not a command this understands\n");
			exit(2);
		}
		free(raw);
	}

	if (ferror(script)) {
		fprintf(stderr, "exfat-populate: reading the script failed\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	FILE *script;
	int rc;

	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("exfat-populate (relan/exfat) %s\n",
				EXFAT_POPULATE_LIBEXFAT_VERSION);
		return 0;
	}
	if (argc != 3)
		usage();

	/* The zone the library converts a timestamp through. Every gate here runs with
	   TZ=UTC set, so this reads UTC; calling it is still required, because libexfat
	   caches the offset at this point rather than per conversion. */
	exfat_tzset();

	rc = exfat_mount(&ef, argv[1], "rw");
	if (rc != 0)
		fail(argv[1], rc);

	if (strcmp(argv[2], "-") == 0) {
		run(stdin);
	} else {
		script = fopen(argv[2], "r");
		if (script == NULL) {
			fprintf(stderr, "exfat-populate: %s: %s\n", argv[2],
					strerror(errno));
			exfat_unmount(&ef);
			return 1;
		}
		run(script);
		fclose(script);
	}

	/* Flushes every dirty node, the allocation bitmap, and the superblock, and clears
	   the dirty flag the mount set. A volume left un-unmounted is one `fsck.exfat`
	   reports as dirty, which would make every gate here fail for the same reason. */
	exfat_unmount(&ef);
	return 0;
}
