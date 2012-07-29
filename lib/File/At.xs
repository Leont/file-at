#include <fcntl.h>
#include <unistd.h>

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

static SV* S_io_fdopen(pTHX_ int fd) {
	PerlIO* pio = PerlIO_fdopen(fd, "r");
	GV* gv = newGVgen("Symbol");
	SV* ret = newRV_noinc((SV*)gv);
	IO* io = GvIOn(gv);
	IoTYPE(io) = '<';
	IoIFP(io) = pio;
	IoOFP(io) = pio;
	return ret;
}
#define io_fdopen(fd) S_io_fdopen(aTHX_ fd)

static int S_get_dirfd(pTHX_ SV* handle, const char* name) {
	IO* io;
	if (!SvOK(handle)) 
		return AT_FDCWD;
	if (!(io = sv_2io(handle))) {
		Perl_croak(aTHX_ "%s attempted on invalid dirhandle", name);
		errno = EINVAL;
		return -1;
	}
	return dirfd(IoDIRP(io));
}
#define get_dirfd(handle, name) S_get_dirfd(aTHX_ handle, name)

/*
 * faccessat, fchmodat, fchownat, fstatat, linkat, mkdirat, mknodat, readlinkat, renameat, symlinkat, unlinkat, utimensat, mkfifoat
 */

#define NANO_SECONDS 1000000000

static NV timespec_to_nv(struct timespec* time) {
	return time->tv_sec + time->tv_nsec / (double)NANO_SECONDS;
}

static void S_sv_to_timespec(pTHX_ SV* input_sv, struct timespec* output) {
	if (!SvOK(input_sv)) {
		output->tv_sec  = 0;
		output->tv_nsec = UTIME_OMIT;
	}
	else if(SvPOK(input_sv) && strEQ(SvPV_nolen(input_sv), "now")) {
		output->tv_sec  = 0;
		output->tv_nsec = UTIME_NOW;
	}
	else {
		NV input = SvNV(input_sv);
		output->tv_sec  = (time_t) floor(input);
		output->tv_nsec = (long) ((input - output->tv_sec) * NANO_SECONDS);
	}
}
#define sv_to_timespec(input, output) S_sv_to_timespec(aTHX_ input, output)

typedef int Dirfd;
typedef int SysRet;

#define constant(value) newCONSTSUB(stash, #value, newSVuv(value))

MODULE = File::At				PACKAGE = File::At

BOOT:
	HV* stash = get_hv("File::At::", FALSE);
	constant(AT_SYMLINK_NOFOLLOW);
#ifdef AT_SYMLINK_FOLLOW
	constant(AT_SYMLINK_FOLLOW);
#endif
	constant(AT_EACCESS);
#ifdef AT_NO_AUTOMOUNT
	constant(AT_NO_AUTOMOUNT);
#endif
	constant(AT_REMOVEDIR);

SV*
sysopenat(dirhandle, pathname, flags, mode = 0600)
	SV* dirhandle;
	const char* pathname
	int flags;
	int mode;
	PROTOTYPE: *@
	PREINIT:
		int dirfd, ret;
	CODE:
	dirfd = get_dirfd(dirhandle, "sysopenat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	ret = openat(dirfd, pathname, flags, mode);
	if (ret == -1)
		XSRETURN_EMPTY;
	RETVAL = io_fdopen(ret);
	OUTPUT:
		RETVAL

const char*
readlinkat(dirhandle, pathname)
	SV* dirhandle;
	const char* pathname
	PROTOTYPE: *@
	PREINIT:
		int dirfd, ret;
		char destination[PATH_MAX];
	CODE:
	dirfd = get_dirfd(dirhandle, "readlinkat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	ret = readlinkat(dirfd, pathname, destination, sizeof destination);
	if (ret == -1)
		XSRETURN_EMPTY;
	RETVAL = destination;
	OUTPUT:
		RETVAL	

int
faccessat(dirhandle, pathname, mode, flags = 0)
	SV* dirhandle;
	const char* pathname
	int mode;
	int flags;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "faccessat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = faccessat(dirfd, pathname, mode, flags);
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

int
unlinkat(dirhandle, pathname, flags = 0)
	SV* dirhandle;
	const char* pathname
	int flags;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "unlinkat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = unlinkat(dirfd, pathname, flags);
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

int
fchmodat(dirhandle, pathname, mode, flags = 0)
	SV* dirhandle;
	const char* pathname
	short mode;
	int flags;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "fchmodat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = fchmodat(dirfd, pathname, mode, flags);
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

int
fchownat(dirhandle, pathname, uid, gid, flags = 0)
	SV* dirhandle;
	const char* pathname
	int uid;
	int gid;
	int flags
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "fchownat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = fchownat(dirfd, pathname, uid, gid, flags);
	OUTPUT:
		RETVAL

SysRet
mkdirat(dirhandle, pathname, flags = 0)
	SV* dirhandle;
	const char* pathname
	int flags;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "mkdirat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = mkdirat(dirfd, pathname, flags);
	OUTPUT:
		RETVAL

int
linkat(dirhandle_from, pathname_from, dirhandle_to, pathname_to, flags = 0)
	SV* dirhandle_from;
	const char* pathname_from
	SV* dirhandle_to;
	const char* pathname_to;
	int flags;
	PROTOTYPE: *$*$$
	PREINIT:
		int dirfd_from, dirfd_to;
	CODE:
	dirfd_from = get_dirfd(dirhandle_from, "linkat");
	dirfd_to = get_dirfd(dirhandle_to, "linkat");
	if (dirfd_from == -1 || dirfd_to == -1)
		XSRETURN_EMPTY;
	RETVAL = linkat(dirfd_from, pathname_from, dirfd_to, pathname_to, flags);
	OUTPUT:
		RETVAL

int
symlinkat(pathname_from, dirhandle_to, pathname_to)
	const char* pathname_from;
	SV* dirhandle_to;
	const char* pathname_to;
	PROTOTYPE: $*$$
	PREINIT:
		int dirfd_to;
	CODE:
	dirfd_to = get_dirfd(dirhandle_to, "symlinkat");
	if (dirfd_to == -1)
		XSRETURN_EMPTY;
	RETVAL = symlinkat(pathname_from, dirfd_to, pathname_to);
	OUTPUT:
		RETVAL

int
renameat(dirhandle_from, pathname_from, dirhandle_to, pathname_to)
	SV* dirhandle_from;
	const char* pathname_from
	SV* dirhandle_to;
	const char* pathname_to;
	PROTOTYPE: $*$
	PREINIT:
		int dirfd_from, dirfd_to;
	CODE:
	dirfd_from = get_dirfd(dirhandle_from, "renameat");
	dirfd_to = get_dirfd(dirhandle_to, "renameat");
	if (dirfd_from == -1 || dirfd_to == -1)
		XSRETURN_EMPTY;
	RETVAL = renameat(dirfd_from, pathname_from, dirfd_to, pathname_to);
	OUTPUT:
		RETVAL

int
mknodat(dirhandle, pathname, mode, dev)
	SV* dirhandle;
	const char* pathname
	short mode;
	int dev;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "mknodat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = mknodat(dirfd, pathname, mode, dev);
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

int
mkfifoat(dirhandle, pathname, mode)
	SV* dirhandle;
	const char* pathname
	short mode;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
	CODE:
	dirfd = get_dirfd(dirhandle, "mkfifoat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	RETVAL = mkfifoat(dirfd, pathname, mode);
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

int
utimensat(dirhandle, pathname, atime_nv, mtime_nv, flags = 0)
	SV* dirhandle;
	const char* pathname
	SV* atime_nv;
	SV* mtime_nv;
	int flags;
	PROTOTYPE: *@
	PREINIT:
		int dirfd;
		struct timespec time_spec[2];
	CODE:
	dirfd = get_dirfd(dirhandle, "utimensat");
	if (dirfd == -1)
		XSRETURN_EMPTY;
	sv_to_timespec(atime_nv, &time_spec[0]);
	sv_to_timespec(mtime_nv, &time_spec[1]);
	RETVAL = utimensat(dirfd, pathname, time_spec, flags);
	
	if (RETVAL == -1)
		XSRETURN_EMPTY;
	OUTPUT:
		RETVAL

