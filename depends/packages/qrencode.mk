package=qrencode
$(package)_version=4.1.1
$(package)_download_path=https://bitcoincore.org/depends-sources
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=e455d9732f8041cf5b9c388e345a641fd15707860f928e94507b1961256a6923
$(package)_build_subdir=build
$(package)_patches=portable_strdup.patch cmake_iconv_package_name.patch cmake_minimum_version.patch

define $(package)_set_vars
$(package)_config_opts = -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF
$(package)_config_opts += -DWITH_TOOLS=OFF -DWITH_TESTS=OFF -DWITHOUT_PNG=ON
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/portable_strdup.patch && \
  patch -p1 < $($(package)_patch_dir)/cmake_iconv_package_name.patch && \
  patch -p1 < $($(package)_patch_dir)/cmake_minimum_version.patch
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
  rm -rf share lib/cmake
endef
