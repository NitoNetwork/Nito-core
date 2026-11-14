package=libxkbcommon
$(package)_version=1.13.2
$(package)_download_path=https://github.com/xkbcommon/libxkbcommon/archive/refs/tags
$(package)_file_name=libxkbcommon-$($(package)_version).tar.gz
$(package)_download_file=xkbcommon-$($(package)_version).tar.gz
$(package)_sha256_hash=acc4d5f7c3cbba5f9f8d08d8bdbeede84ecede46792f47929aa9321873385528
$(package)_dependencies=libxcb native_meson
$(package)_build_subdir=build

define $(package)_set_vars
$(package)_config_opts = --prefix=$($($(package)_type)_prefix) --libdir=lib
$(package)_config_opts += --buildtype=release --wrap-mode=nodownload
$(package)_config_opts += -Ddefault_library=static -Dwerror=true
$(package)_config_opts += -Denable-tools=false -Denable-docs=false
$(package)_config_opts += -Denable-wayland=false -Denable-xkbregistry=false
$(package)_config_opts += -Denable-bash-completion=false -Denable-x11=true
$(package)_config_opts += -Dxkb-config-root=/usr/share/X11/xkb
$(package)_config_opts += -Dxkb-config-extra-path=/etc/xkb
$(package)_config_opts += -Dx-locale-root=/usr/share/X11/locale
endef

define $(package)_preprocess_cmds
  if test "$(host)" != "$(build)"; then \
    printf '%s\n' \
      '[binaries]' \
      "c = '$($(package)_cc)'" \
      "ar = '$($(package)_ar)'" \
      "strip = '$($($(package)_type)_STRIP)'" \
      "pkg-config = 'pkg-config'" \
      '[properties]' \
      'needs_exe_wrapper = true' \
      '[host_machine]' \
      "system = '$(host_os)'" \
      "cpu_family = '$(host_arch)'" \
      "cpu = '$(host_arch)'" \
      "endian = 'little'" \
      > nito-meson-cross.ini; \
  fi
endef

define $(package)_config_cmds
  env CC="$($(package)_cc)" \
    CFLAGS="$($(package)_cppflags) $($(package)_cflags)" \
    LDFLAGS="$($(package)_ldflags)" \
    meson setup .. $($(package)_config_opts) \
      $(if $(filter-out $(build),$(host)),--cross-file=../nito-meson-cross.ini,)
endef

define $(package)_build_cmds
  meson compile -j $(if $(JOBS),$(JOBS),1) xkbcommon xkbcommon-x11
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
