package=libxcb_util_cursor
$(package)_version=0.1.6
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=xcb-util-cursor-$($(package)_version).tar.xz
$(package)_sha256_hash=fdeb8bd127873519be5cc70dcd0d3b5d33b667877200f9925a59fdcad8f7a933
$(package)_dependencies=libxcb libxcb_util_image libxcb_util_render
$(package)_patches=static_gperf_lookup.patch

define $(package)_set_vars
$(package)_config_opts=--disable-shared --enable-static --disable-devel-docs
$(package)_config_opts += --disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub . && \
  patch -p1 < $($(package)_patch_dir)/static_gperf_lookup.patch
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-data && \
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  install -m 644 cursor/.libs/libxcb-cursor.a $($(package)_staging_prefix_dir)/lib
endef

define $(package)_postprocess_cmds
  rm -rf share/man share/doc lib/*.la
endef
