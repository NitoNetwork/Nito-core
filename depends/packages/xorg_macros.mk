package=xorg_macros
$(package)_version=1.20.2
$(package)_download_path=https://xorg.freedesktop.org/archive/individual/util
$(package)_file_name=util-macros-$($(package)_version).tar.xz
$(package)_sha256_hash=9ac269eba24f672d7d7b3574e4be5f333d13f04a7712303b1821b2a51ac82e8e

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
