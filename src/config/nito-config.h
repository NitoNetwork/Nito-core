/* src/config/nito-config.h.  Generated from nito-config.h.in by configure.  */
/* src/config/nito-config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef BITCOIN_CONFIG_H

#define BITCOIN_CONFIG_H

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Defined to avoid Boost::Process trying to use Boost Filesystem */
#define BOOST_PROCESS_USE_STD_FS 1

/* Version Build */
#define CLIENT_VERSION_BUILD 0

/* Version is release */
#define CLIENT_VERSION_IS_RELEASE true

/* Major version */
#define CLIENT_VERSION_MAJOR 1

/* Minor version */
#define CLIENT_VERSION_MINOR 0

/* Copyright holder(s) before %s replacement */
#define COPYRIGHT_HOLDERS "The %s developers"

/* Copyright holder(s) */
#define COPYRIGHT_HOLDERS_FINAL "The Nito Core developers"

/* Replacement for %s in copyright holders string */
#define COPYRIGHT_HOLDERS_SUBSTITUTION "Nito Core"

/* Copyright year */
#define COPYRIGHT_YEAR 2024

/* Define this symbol to build code that uses ARMv8 SHA-NI intrinsics */
/* #undef ENABLE_ARM_SHANI */

/* Define this symbol to build code that uses AVX2 intrinsics */
#define ENABLE_AVX2 1

/* Define if external signer support is enabled */
#define ENABLE_EXTERNAL_SIGNER 1

/* Define this symbol to build code that uses SSE4.1 intrinsics */
#define ENABLE_SSE41 1

/* Define to 1 to enable tracepoints for Userspace, Statically Defined Tracing
   */
/* #undef ENABLE_TRACING */

/* Define to 1 to enable wallet functions */
/* #undef ENABLE_WALLET */

/* Define this symbol to build code that uses x86 SHA-NI intrinsics */
#define ENABLE_X86_SHANI 1

/* Define this symbol to enable ZMQ functions */
#define ENABLE_ZMQ 1

/* define if the Boost library is available */
#define HAVE_BOOST /**/

/* Define this symbol if you have __builtin_clzl */
#define HAVE_BUILTIN_CLZL 1

/* Define this symbol if you have __builtin_clzll */
#define HAVE_BUILTIN_CLZLL 1

/* Define this symbol if clmul instructions can be used */
#define HAVE_CLMUL 1

/* Define this symbol if the consensus lib has been built */
#define HAVE_CONSENSUS_LIB 1

/* define if the compiler supports basic C++20 syntax */
#define HAVE_CXX20 1

/* Define to 1 if you have the declaration of `fork', and to 0 if you don't.
   */
#define HAVE_DECL_FORK 1

/* Define to 1 if you have the declaration of `freeifaddrs', and to 0 if you
   don't. */
#define HAVE_DECL_FREEIFADDRS 1

/* Define to 1 if you have the declaration of `getifaddrs', and to 0 if you
   don't. */
#define HAVE_DECL_GETIFADDRS 1

/* Define to 1 if you have the declaration of `pipe2', and to 0 if you don't.
   */
#define HAVE_DECL_PIPE2 1

/* Define to 1 if you have the declaration of `setsid', and to 0 if you don't.
   */
#define HAVE_DECL_SETSID 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 1

/* Define if the visibility attribute is supported. */
#define HAVE_DEFAULT_VISIBILITY_ATTRIBUTE 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define if the dllexport attribute is supported. */
/* #undef HAVE_DLLEXPORT_ATTRIBUTE */

/* Define this symbol if evhttp_connection_get_peer expects const char** */
/* #undef HAVE_EVHTTP_CONNECTION_GET_PEER_CONST_CHAR */

/* Define to 1 if fdatasync is available. */
#define HAVE_FDATASYNC 1

/* Define this symbol if the BSD getentropy system call is available with
   sys/random.h */
#define HAVE_GETENTROPY_RAND 1

/* Define this symbol if the Linux getrandom function call is available */
#define HAVE_GETRANDOM 1

/* Define this symbol if gmtime_r is available */
#define HAVE_GMTIME_R 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `advapi32' library (-ladvapi32). */
/* #undef HAVE_LIBADVAPI32 */

/* Define to 1 if you have the `comctl32' library (-lcomctl32). */
/* #undef HAVE_LIBCOMCTL32 */

/* Define to 1 if you have the `comdlg32' library (-lcomdlg32). */
/* #undef HAVE_LIBCOMDLG32 */

/* Define to 1 if you have the `gdi32' library (-lgdi32). */
/* #undef HAVE_LIBGDI32 */

/* Define to 1 if you have the `iphlpapi' library (-liphlpapi). */
/* #undef HAVE_LIBIPHLPAPI */

/* Define to 1 if you have the `kernel32' library (-lkernel32). */
/* #undef HAVE_LIBKERNEL32 */

/* Define to 1 if you have the `ole32' library (-lole32). */
/* #undef HAVE_LIBOLE32 */

/* Define to 1 if you have the `oleaut32' library (-loleaut32). */
/* #undef HAVE_LIBOLEAUT32 */

/* Define to 1 if you have the `shell32' library (-lshell32). */
/* #undef HAVE_LIBSHELL32 */

/* Define to 1 if you have the `shlwapi' library (-lshlwapi). */
/* #undef HAVE_LIBSHLWAPI */

/* Define to 1 if you have the `user32' library (-luser32). */
/* #undef HAVE_LIBUSER32 */

/* Define to 1 if you have the `uuid' library (-luuid). */
/* #undef HAVE_LIBUUID */

/* Define to 1 if you have the `winmm' library (-lwinmm). */
/* #undef HAVE_LIBWINMM */

/* Define to 1 if you have the `ws2_32' library (-lws2_32). */
/* #undef HAVE_LIBWS2_32 */

/* Define this symbol if you have malloc_info */
#define HAVE_MALLOC_INFO 1

/* Define this symbol if you have mallopt with M_ARENA_MAX */
#define HAVE_MALLOPT_ARENA_MAX 1

/* Define to 1 if you have the <miniupnpc/miniupnpc.h> header file. */
/* #undef HAVE_MINIUPNPC_MINIUPNPC_H */

/* Define to 1 if you have the <miniupnpc/upnpcommands.h> header file. */
/* #undef HAVE_MINIUPNPC_UPNPCOMMANDS_H */

/* Define to 1 if you have the <miniupnpc/upnperrors.h> header file. */
/* #undef HAVE_MINIUPNPC_UPNPERRORS_H */

/* Define to 1 if you have the <natpmp.h> header file. */
#define HAVE_NATPMP_H 1

/* Define to 1 if O_CLOEXEC flag is available. */
#define HAVE_O_CLOEXEC 1

/* Define this symbol if you have posix_fallocate */
#define HAVE_POSIX_FALLOCATE 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Have PTHREAD_PRIO_INHERIT. */
#define HAVE_PTHREAD_PRIO_INHERIT 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define if you have `strerror_r'. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define this symbol to build code that uses getauxval) */
#define HAVE_STRONG_GETAUXVAL 1

/* Define this symbol if the BSD sysctl() is available */
/* #undef HAVE_SYSCTL */

/* Define this symbol if the BSD sysctl(KERN_ARND) is available */
/* #undef HAVE_SYSCTL_ARND */

/* Define to 1 if std::system or ::wsystem is available. */
#define HAVE_SYSTEM 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/resources.h> header file. */
/* #undef HAVE_SYS_RESOURCES_H */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
/* #undef HAVE_SYS_SYSCTL_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/vmmeter.h> header file. */
/* #undef HAVE_SYS_VMMETER_H */

/* Define if thread_local is supported. */
#define HAVE_THREAD_LOCAL 1

/* Define to 1 if you have the `timingsafe_bcmp' function. */
/* #undef HAVE_TIMINGSAFE_BCMP */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <vm/vm_param.h> header file. */
/* #undef HAVE_VM_VM_PARAM_H */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/NitoNetwork/core/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "Nito Core"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Nito Core 1.27.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "nito"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://nitocore.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.27.0"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Define this symbol if the qt platform is android */
/* #undef QT_QPA_PLATFORM_ANDROID */

/* Define this symbol if the qt platform is cocoa */
/* #undef QT_QPA_PLATFORM_COCOA */

/* Define this symbol if the minimal qt platform exists */
/* #undef QT_QPA_PLATFORM_MINIMAL */

/* Define this symbol if the qt platform is windows */
/* #undef QT_QPA_PLATFORM_WINDOWS */

/* Define this symbol if the qt platform is xcb */
/* #undef QT_QPA_PLATFORM_XCB */

/* Define this symbol if qt plugins are static */
/* #undef QT_STATICPLUGIN */

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
#define STRERROR_R_CHAR_P 1

/* Define if BDB support should be compiled in */
/* #undef USE_BDB */

/* Define if dbus support should be compiled in */
/* #undef USE_DBUS */

/* Define to 1 if UPnP support should be compiled in. */
#define USE_NATPMP 1

/* Define if QR support should be compiled in */
/* #undef USE_QRCODE */

/* Define if sqlite support should be compiled in */
/* #undef USE_SQLITE */

/* Define to 1 if UPnP support should be compiled in. */
/* #undef USE_UPNP */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

#endif //BITCOIN_CONFIG_H
