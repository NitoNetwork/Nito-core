package=libevent
$(package)_version=2.1.13-stable
$(package)_download_path=https://github.com/libevent/libevent/releases/download/release-$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c
$(package)_build_subdir=build
$(package)_patches=socketpair_array_bound.patch gcc_diagnostic_version.patch mingw_warning_fixes.patch cmake_archive_build.patch fix_pkgconfig_system_libs.patch macos_arc4random_stir.patch

define $(package)_set_vars
  $(package)_config_opts := -DCMAKE_BUILD_TYPE=None -DEVENT__LIBRARY_TYPE=STATIC
  $(package)_config_opts += -DEVENT__DISABLE_OPENSSL=ON
  $(package)_config_opts += -DEVENT__DISABLE_BENCHMARK=ON
  $(package)_config_opts += -DEVENT__DISABLE_TESTS=ON
  $(package)_config_opts += -DEVENT__DISABLE_REGRESS=ON
  $(package)_config_opts += -DEVENT__DISABLE_SAMPLES=ON
  $(package)_config_opts += -DEVENT__DISABLE_DEBUG_MODE=ON
  $(package)_config_opts_darwin += $(if $(filter darwin,$(build_os)),-DEVENT__FORCE_KQUEUE_CHECK=ON)
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/socketpair_array_bound.patch && \
  patch -p1 < $($(package)_patch_dir)/gcc_diagnostic_version.patch && \
  patch -p1 < $($(package)_patch_dir)/mingw_warning_fixes.patch && \
  patch -p1 < $($(package)_patch_dir)/cmake_archive_build.patch && \
  patch -p1 < $($(package)_patch_dir)/fix_pkgconfig_system_libs.patch && \
  patch -p1 < $($(package)_patch_dir)/macos_arc4random_stir.patch
endef

define $(package)_config_cmds
  $($(package)_cmake) -GNinja -S .. -B .
endef

define $(package)_build_cmds
  cmake --build . --parallel $(if $(JOBS),$(JOBS),1)
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) cmake --install .
endef

define $(package)_postprocess_cmds
  rm -rf lib/cmake lib/pkgconfig/*.pc.in && \
  rm -f include/ev*.h include/event2/*_compat.h
endef
