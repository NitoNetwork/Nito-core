package=expat
$(package)_version=2.8.5
$(package)_download_path=https://github.com/libexpat/libexpat/releases/download/R_$(subst .,_,$($(package)_version))
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=1e727b8933ec51a77a9a9d9afcf8e688bce45d907c13e36ab7393fe36e703182
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts := -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts += -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_BUILD_EXAMPLES=OFF
  $(package)_config_opts += -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_DOCS=OFF
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
