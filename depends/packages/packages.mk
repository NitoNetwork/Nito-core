packages:=

boost_packages = boost

libevent_packages = libevent

qrencode_linux_packages = qrencode
qrencode_android_packages = qrencode
qrencode_darwin_packages = qrencode
qrencode_mingw32_packages = qrencode

qt_linux_packages:=qt expat xorg_macros libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm libxcb_util_cursor
qt_android_packages=qt
qt_darwin_packages=qt
qt_mingw32_packages=qt

qt_native_packages=
qt_linux_native_packages=native_meson
ifeq ($(build_os),darwin)
qt_darwin_native_packages=native_qt
endif
# Compare canonical triples so aliases such as arm64/aarch64 do not turn a
# native build into a cross build with an isolated target toolchain.
ifneq ($(canonical_host),$(build))
qt_native_packages=native_qt
endif

bdb_packages=bdb
sqlite_packages=sqlite
utf8proc_packages=utf8proc

zmq_packages=zeromq

upnp_packages=miniupnpc
natpmp_packages=libnatpmp

multiprocess_packages = libmultiprocess capnp
multiprocess_native_packages = native_libmultiprocess native_capnp

usdt_linux_packages=systemtap

darwin_native_packages =

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_libtapi

ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
darwin_native_packages+= native_llvm
endif

endif
