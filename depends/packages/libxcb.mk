package=libxcb
$(package)_version=1.17.0
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=599ebf9996710fea71622e6e184f3a8ad5b43d0e5fa8c4e407123c88a59a6d55
$(package)_dependencies=xcb_proto libXau
$(package)_patches=remove_pthread_stubs.patch checked_setup_error_write.patch static_xau_dependency.patch

define $(package)_set_vars
$(package)_config_opts=--disable-shared --enable-static --disable-devel-docs
$(package)_config_opts += --disable-dependency-tracking --enable-option-checking
$(package)_config_opts += --disable-composite --disable-damage --disable-dpms
$(package)_config_opts += --disable-dri2 --disable-dri3 --disable-glx
$(package)_config_opts += --disable-present --disable-record --disable-resource
$(package)_config_opts += --disable-screensaver --disable-xevie --disable-xfree86-dri
$(package)_config_opts += --disable-xinput --disable-xprint --disable-selinux
$(package)_config_opts += --disable-xtest --disable-xv --disable-xvmc --disable-xinerama
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub build-aux && \
  patch -p1 -i $($(package)_patch_dir)/remove_pthread_stubs.patch && \
  patch -p1 -i $($(package)_patch_dir)/checked_setup_error_write.patch && \
  patch -p1 -i $($(package)_patch_dir)/static_xau_dependency.patch
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
  install -m 644 src/.libs/libxcb*.a $($(package)_staging_prefix_dir)/lib
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
