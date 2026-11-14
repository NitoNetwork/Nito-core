package=freetype
$(package)_version=2.14.3
$(package)_download_path=https://download.savannah.gnu.org/releases/$(package)
$(package)_fallback_download_path=https://mirror.netcologne.de/savannah/$(package) https://mirror.csclub.uwaterloo.ca/nongnu/$(package)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts := -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts += -DFT_DISABLE_ZLIB=TRUE -DFT_DISABLE_PNG=TRUE
  $(package)_config_opts += -DFT_DISABLE_HARFBUZZ=TRUE -DFT_DISABLE_BZIP2=TRUE
  $(package)_config_opts += -DFT_DISABLE_BROTLI=TRUE
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
