package=libXau
$(package)_version=1.0.12
$(package)_download_path=https://xorg.freedesktop.org/releases/individual/lib
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=74d0e4dfa3d39ad8939e99bda37f5967aba528211076828464d2777d477fc0fb
$(package)_dependencies=xproto

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --disable-lint-library --without-lint
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
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
  install -m 644 .libs/libXau.a $($(package)_staging_prefix_dir)/lib
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
