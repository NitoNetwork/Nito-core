package=sqlite
$(package)_version=3380500
$(package)_download_path=https://sqlite.org/2022/
$(package)_file_name=sqlite-autoconf-$($(package)_version).tar.gz
$(package)_sha256_hash=5af07de982ba658fd91a03170c945f99c971f6955bc79df3266544373e39869c

define $(package)_set_vars
$(package)_config_opts=--disable-shared --disable-readline --disable-dynamic-extensions --enable-option-checking
$(package)_config_opts+= --disable-rtree --disable-fts4 --disable-fts5
$(package)_config_opts_linux=--with-pic
$(package)_config_opts_freebsd=--with-pic
$(package)_config_opts_netbsd=--with-pic
$(package)_config_opts_openbsd=--with-pic
# We avoid using `--enable-debug` because it overrides CFLAGS, a behavior we want to prevent.
$(package)_cflags_debug += -g
$(package)_cppflags_debug += -DSQLITE_DEBUG
$(package)_cppflags+=-DSQLITE_DQS=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED
$(package)_cppflags+=-DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_JSON -DSQLITE_LIKE_DOESNT_MATCH_BLOBS
$(package)_cppflags+=-DSQLITE_OMIT_DECLTYPE -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_AUTOINIT
$(package)_config_env += STRIP="$($($(package)_type)_STRIP)"
$(package)_config_env_mingw32 = MANIFEST_TOOL=:
$(package)_config_env_darwin = lt_cv_apple_cc_single_mod=no
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) libsqlite3.la
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include $($(package)_staging_prefix_dir)/lib/pkgconfig && \
  install -m 644 sqlite3.h sqlite3ext.h $($(package)_staging_prefix_dir)/include && \
  install -m 644 .libs/libsqlite3.a $($(package)_staging_prefix_dir)/lib && \
  install -m 644 sqlite3.pc $($(package)_staging_prefix_dir)/lib/pkgconfig
endef

define $(package)_postprocess_cmds
  rm -f lib/*.la
endef
