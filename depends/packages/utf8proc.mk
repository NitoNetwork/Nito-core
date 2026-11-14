package=utf8proc
$(package)_version=2.11.3
$(package)_download_path=https://github.com/JuliaStrings/utf8proc/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=415189fd2c85cd6ee5ff26af500fa387de9ada1e3e316e93f7338551481d557d
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts := -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts += -DUTF8PROC_ENABLE_TESTING=OFF -DUTF8PROC_INSTALL=ON
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
