package=zeromq
$(package)_version=4.3.5
$(package)_download_path=https://github.com/zeromq/libzmq/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=6653ef5910f17954861fe72332e68b03ca6e4d9c7160eb3a8de5a5a913bfab43
$(package)_patches=remove_libstd_link.patch guard_unsubscription_size.patch macos_missing_braces.patch

define $(package)_set_vars
  $(package)_config_opts = --without-docs --disable-shared --disable-valgrind
  $(package)_config_opts += --disable-perf --disable-curve-keygen --disable-curve --disable-libbsd
  $(package)_config_opts += --without-libsodium --without-libgssapi_krb5 --without-pgm --without-norm --without-vmci
  $(package)_config_opts += --disable-libunwind --disable-radix-tree --without-gcov --disable-dependency-tracking
  $(package)_config_opts += --disable-Werror --disable-drafts --enable-option-checking
  $(package)_config_env += libzmq_getconf=getconf
  $(package)_config_env += PKG_CONFIG="pkg-config --static"
  $(package)_config_env += STRIP="$($($(package)_type)_STRIP)"
  $(package)_config_env_mingw32 = MANIFEST_TOOL=:
  $(package)_config_env_darwin = lt_cv_apple_cc_single_mod=no
  $(package)_config_opts_linux=--with-pic
  $(package)_config_opts_freebsd=--with-pic
  $(package)_config_opts_netbsd=--with-pic
  $(package)_config_opts_openbsd=--with-pic
  $(package)_config_opts_android=--with-pic
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/remove_libstd_link.patch && \
  patch -p1 < $($(package)_patch_dir)/guard_unsubscription_size.patch && \
  patch -p1 < $($(package)_patch_dir)/macos_missing_braces.patch
endef

define $(package)_config_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub config && \
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) src/libzmq.la
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include $($(package)_staging_prefix_dir)/lib/pkgconfig && \
  install -m 644 include/zmq.h include/zmq_utils.h $($(package)_staging_prefix_dir)/include && \
  install -m 644 src/.libs/libzmq.a $($(package)_staging_prefix_dir)/lib && \
  install -m 644 src/libzmq.pc $($(package)_staging_prefix_dir)/lib/pkgconfig
endef

define $(package)_postprocess_cmds
  rm -rf bin share lib/*.la
endef
