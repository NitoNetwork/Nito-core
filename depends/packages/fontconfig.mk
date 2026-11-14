package=fontconfig
$(package)_version=2.18.2
$(package)_download_path=https://gitlab.freedesktop.org/api/v4/projects/890/packages/generic/fontconfig/$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=cf8e6576ef0484c15079bdaf77cd9c51c464df5365814ada4d3ee7331ea31eb5
$(package)_dependencies=freetype expat native_meson
$(package)_patches=nito_warning_fixes.patch
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts = --prefix=$($($(package)_type)_prefix) --libdir=lib
  $(package)_config_opts += --buildtype=release --wrap-mode=nodownload
  $(package)_config_opts += --sysconfdir=/etc --localstatedir=/var --datadir=/usr/share
  $(package)_config_opts += -Ddefault_library=static -Dwerror=true
  $(package)_config_opts += -Ddoc=disabled -Ddoc-txt=disabled -Ddoc-man=disabled
  $(package)_config_opts += -Ddoc-pdf=disabled -Ddoc-html=disabled -Dnls=disabled
  $(package)_config_opts += -Dtests=disabled -Dtests-bwrap=disabled
  $(package)_config_opts += -Dtests-external-fonts=disabled -Dtools=disabled
  $(package)_config_opts += -Dcache-build=disabled -Diconv=disabled
  $(package)_config_opts += -Dxml-backend=expat -Dfontations=disabled
  $(package)_config_opts += -Dbaseconfig-dir=/etc/fonts -Dconfig-dir=/etc/fonts/conf.d
  $(package)_config_opts += -Dtemplate-dir=/usr/share/fontconfig/conf.avail
  $(package)_config_opts += -Dcache-dir=/var/cache/fontconfig
  $(package)_config_opts += -Ddefault-fonts-dirs=/usr/share/fonts
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/nito_warning_fixes.patch && \
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
  meson compile -j $(if $(JOBS),$(JOBS),1)
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild
endef

define $(package)_postprocess_cmds
  rm -rf bin etc share var lib/*.la
endef
