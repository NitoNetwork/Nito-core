package=qt
$(package)_version=6.8.4
$(package)_download_path=https://download.qt.io/archive/qt/6.8/$($(package)_version)/single
$(package)_fallback_download_path=https://ftp.fau.de/qtproject/archive/qt/6.8/$($(package)_version)/single
$(package)_file_name=qt-everywhere-opensource-src-$($(package)_version).tar.xz
$(package)_sha256_hash=1da37a32a583e7856d6fc13357c8ff6ad3ef7b877b8d276713b85026426d5246
$(package)_patches=md4c_reference_definition_init.patch mingw_no_cpp_winrt_warning.patch qhttpheaders_compare_views.patch qmimemagicrule_compare_views.patch static_xcb_dependencies.patch macos_modern_apis.patch CVE-2026-78253.patch CVE-2026-76151.patch CVE-2026-19248.patch
$(package)_linux_dependencies=freetype fontconfig libxcb libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm libxcb_util_cursor
ifeq ($(canonical_host),$(build))
$(package)_darwin_dependencies=native_qt
endif
ifneq ($(canonical_host),$(build))
$(package)_dependencies += native_qt
endif

define $(package)_set_vars
$(package)_config_env = QT_MAC_SDK_NO_VERSION_CHECK=1
$(package)_config_opts_release = -release
$(package)_config_opts_debug = -debug
$(package)_config_opts += -opensource
$(package)_config_opts += -confirm-license
$(package)_config_opts += -static
$(package)_config_opts += -prefix $(host_prefix)
$(package)_config_opts += -cmake-generator Ninja
$(package)_config_opts += -nomake examples
$(package)_config_opts += -nomake tests
# Target PCH files can exhaust hosted-runner storage in both native x86_64
# sanitizer builds and ARM64 builds. This changes no Qt feature or test scope.
$(package)_config_opts += $(if $(filter linux,$(host_os)),-no-pch)
$(package)_config_opts += -no-dbus
$(package)_config_opts += -no-icu
$(package)_config_opts += -no-opengl
$(package)_config_opts += -no-openssl
$(package)_config_opts += -no-feature-printsupport
$(package)_config_opts += -no-feature-sql
$(package)_config_opts += -qt-harfbuzz
$(package)_config_opts += -qt-libpng
$(package)_config_opts += -qt-pcre
$(package)_config_opts += -qt-zlib
$(package)_config_opts += -submodules qtbase
$(package)_cmake_opts += -DQT_BUILD_EXAMPLES_BY_DEFAULT=OFF
$(package)_cmake_opts += -DQT_BUILD_TESTS_BY_DEFAULT=OFF
$(package)_cmake_opts += -DCMAKE_INSTALL_LIBDIR=lib
$(package)_cmake_opts += $(if $(filter darwin,$(host_os)),-DCMAKE_OSX_DEPLOYMENT_TARGET=$(OSX_MIN_VERSION))

ifneq ($(canonical_host),$(build))
$(package)_config_opts += -qt-host-path $(build_prefix)/qt-host/qtbase
$(package)_cmake_opts += -DCMAKE_TOOLCHAIN_FILE=$($(package)_build_dir)/nito-qt6-toolchain.cmake
$(package)_cmake_opts += -DCMAKE_FIND_ROOT_PATH=$(host_prefix)
$(package)_cmake_opts += -DCMAKE_PREFIX_PATH=$(host_prefix)
endif

$(package)_config_opts_linux = -xcb
$(package)_config_opts_linux += -no-feature-gssapi
$(package)_config_opts_linux += -no-feature-xlib
$(package)_config_opts_linux += -system-freetype
$(package)_config_opts_linux += -fontconfig
$(package)_config_opts_linux += -no-feature-vulkan
$(package)_config_opts_linux += -pkg-config

$(package)_config_opts_mingw32 = -no-freetype
$(package)_config_opts_mingw32 += -no-feature-vulkan
$(package)_config_opts_mingw32 += -pkg-config
# Do not let native Homebrew packages enter Qt's static Darwin metadata.
$(package)_config_opts_darwin = -no-framework
$(package)_config_opts_darwin += -no-glib
$(package)_config_opts_darwin += -no-zstd
$(package)_config_opts_darwin += -no-feature-freetype
$(package)_config_opts_darwin += -no-pkg-config
$(package)_config_opts_darwin += -qt-libjpeg
endef

# Keep compiler commands as CMake lists: Darwin appends required SDK options
# to clang, and quoting the complete command turns it into a nonexistent path.
define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/md4c_reference_definition_init.patch && \
  patch -p1 < $($(package)_patch_dir)/mingw_no_cpp_winrt_warning.patch && \
  patch -p1 < $($(package)_patch_dir)/qhttpheaders_compare_views.patch && \
  patch -p1 < $($(package)_patch_dir)/qmimemagicrule_compare_views.patch && \
  patch -p1 < $($(package)_patch_dir)/static_xcb_dependencies.patch && \
  patch -p1 < $($(package)_patch_dir)/macos_modern_apis.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-78253.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-76151.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-19248.patch && \
  if test "$(canonical_host)" != "$(build)"; then \
    printf '%s\n' \
      'set(CMAKE_SYSTEM_NAME $($(host_os)_cmake_system))' \
      'set(CMAKE_SYSTEM_PROCESSOR $(host_arch))' \
      'set(CMAKE_C_COMPILER $($(package)_cc))' \
      'set(CMAKE_CXX_COMPILER $($(package)_cxx))' \
      'set(CMAKE_AR "$($(package)_ar)")' \
      'set(CMAKE_RANLIB "$($(package)_ranlib)")' \
      'set(CMAKE_STRIP "$($($(package)_type)_STRIP)")' \
      'set(CMAKE_FIND_ROOT_PATH "$(host_prefix)")' \
      'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' \
      'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' \
      'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' \
      'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)' \
      > nito-qt6-toolchain.cmake; \
    if test "$(host_os)" = "mingw32"; then \
      printf '%s\n' 'set(CMAKE_RC_COMPILER "$(host)-windres")' >> nito-qt6-toolchain.cmake; \
    fi; \
  fi
endef

define $(package)_config_cmds
  ./configure $($(package)_config_opts) -- $($(package)_cmake_opts)
endef

define $(package)_build_cmds
  cmake --build . --parallel $(if $(JOBS),$(JOBS),1)
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) cmake --install . && \
  if test "$(host_os)" = "darwin"; then \
    translation_src_dir=qttranslations/translations; \
    translation_dst_dir="$($(package)_staging_prefix_dir)/translations"; \
    if ! test -d "$$$$translation_src_dir"; then \
      echo "missing QtBase translation sources"; \
      exit 1; \
    fi; \
    mkdir -p "$$$$translation_dst_dir"; \
    qt_translations_staged=; \
    for ts in "$$$$translation_src_dir"/qtbase_*.ts; do \
      if ! test -f "$$$$ts"; then continue; fi; \
      qm=$$$${ts##*/}; \
      qm=$$$${qm%.ts}.qm; \
      "$(build_prefix)/bin/lrelease" "$$$$ts" -qm "$$$$translation_dst_dir/$$$$qm"; \
      if ! test -s "$$$$translation_dst_dir/$$$$qm"; then \
        echo "empty QtBase translation: $$$$qm"; \
        exit 1; \
      fi; \
      qt_translations_staged=yes; \
    done; \
    if test -z "$$$$qt_translations_staged"; then \
      echo "no QtBase translations were staged"; \
      exit 1; \
    fi; \
  fi
endef

# Nito's configure probes each Qt module separately. On Darwin, keep one
# relocated and deduplicated private closure in Qt6Core.pc so Apple ld never
# receives the same static archive from every module's pkg-config result.
define $(package)_postprocess_cmds
  mkdir -p lib/pkgconfig && \
  qt_libs= && \
  for lib in lib/libQt6*.a lib/Qt6*.a; do \
    if test -f "$$$$lib"; then \
      name=$$$${lib##*/}; \
      name=$$$${name#lib}; \
      name=$$$${name%.a}; \
      case " $$$$qt_libs " in *" -l$$$$name "*) ;; *) qt_libs="$$$$qt_libs -l$$$$name" ;; esac; \
    fi; \
  done && \
  qt_plugin_libs= && \
  for dir in plugins/platforms plugins/styles plugins/imageformats plugins/generic plugins/platforminputcontexts plugins/networkinformation plugins/tls; do \
    if test -d "$$$$dir"; then \
      qt_plugin_libs="$$$$qt_plugin_libs -L$(host_prefix)/$$$$dir"; \
      for lib in "$$$$dir"/lib*.a "$$$$dir"/*.a; do \
        if test -f "$$$$lib"; then \
          name=$$$${lib##*/}; \
          name=$$$${name#lib}; \
          name=$$$${name%.a}; \
          case "$(host_os):$$$$name" in \
            darwin:qcocoa|darwin:qmacstyle|darwin:qminimal) ;; \
            *) case " $$$$qt_plugin_libs " in *" -l$$$$name "*) ;; *) qt_plugin_libs="$$$$qt_plugin_libs -l$$$$name" ;; esac ;; \
          esac; \
        fi; \
      done; \
    fi; \
  done && \
  qt_host_bins="$(host_prefix)/bin" && \
  if test -d "$(host_prefix)/native/bin"; then \
    qt_host_bins="$(host_prefix)/native/bin"; \
  elif test -d "$(host_prefix)/libexec"; then \
    qt_host_bins="$(host_prefix)/libexec"; \
  fi && \
  qt_requires_private= && \
  qt_object_private= && \
  qt_cocoa_resource_private= && \
  qt_system_private= && \
  qt_link_group_open="-Wl,--start-group" && \
  qt_link_group_close="-Wl,--end-group" && \
  case "$(host_os)" in \
    darwin) \
      qt_link_group_open=; \
      qt_link_group_close=; \
      qt_libs=; \
      qt_prl_found=; \
      qt_expect_framework=; \
      for prl in lib/libQt6*.prl plugins/platforms/*.prl plugins/styles/*.prl plugins/imageformats/*.prl plugins/generic/*.prl plugins/platforminputcontexts/*.prl plugins/networkinformation/*.prl plugins/tls/*.prl; do \
        if test -f "$$$$prl"; then \
          qt_prl_found=yes; \
          prl_libs=$$$$(sed -n 's/^QMAKE_PRL_LIBS = //p' "$$$$prl" | sed \
            -e 's|[$$$$][$$$$][[]QT_INSTALL_LIBS[]]|$(host_prefix)/lib|g' \
            -e 's|[$$$$][$$$$][[]QT_INSTALL_PLUGINS[]]|$(host_prefix)/plugins|g' \
            -e 's|[$$$$][$$$$][[]QT_INSTALL_QML[]]|$(host_prefix)/qml|g' \
            -e 's|[$$$$][$$$$][[]QT_INSTALL_PREFIX[]]|$(host_prefix)|g'); \
          for token in $$$$prl_libs; do \
            if test -n "$$$$qt_expect_framework"; then \
              case " $$$$qt_system_private " in \
                *" -framework $$$$token "*) ;; \
                *) qt_system_private="$$$$qt_system_private -framework $$$$token" ;; \
              esac; \
              qt_expect_framework=; \
              continue; \
            fi; \
            case "$$$$token" in \
              -framework) qt_expect_framework=yes ;; \
              -L"$(host_prefix)"/*) ;; \
              "$(host_prefix)"/plugins/*/lib*.a) ;; \
              "$(host_prefix)"/lib/lib*.a) \
                name=$$$${token##*/}; \
                name=$$$${name#lib}; \
                name=$$$${name%.a}; \
                case "$$$$name" in \
                  Qt6Core|Qt6Gui|Qt6Network|Qt6Test|Qt6Widgets) ;; \
                  *) \
                    qt_archive="-l$$$$name"; \
                    case " $$$$qt_libs " in *" $$$$qt_archive "*) ;; *) qt_libs="$$$$qt_libs $$$$qt_archive" ;; esac \
                    ;; \
                esac \
                ;; \
              "$(host_prefix)"/lib/objects-*/QCocoaIntegrationPlugin_resources_*/*) \
                if test -n "$$$$qt_cocoa_resource_private" && test "$$$$qt_cocoa_resource_private" != "$$$$token"; then \
                  echo "multiple Qt Darwin Cocoa resource initializers"; \
                  exit 1; \
                fi; \
                qt_cocoa_resource_private="$$$$token" \
                ;; \
              "$(host_prefix)"/*.o) \
                case " $$$$qt_object_private " in *" $$$$token "*) ;; *) qt_object_private="$$$$qt_object_private $$$$token" ;; esac \
                ;; \
              "$(host_prefix)"/*) \
                echo "unsupported Qt Darwin private path: $$$$token"; \
                exit 1 \
                ;; \
              -L*|/*) \
                echo "non-relocatable Qt Darwin private path: $$$$token"; \
                exit 1 \
                ;; \
              -lQt6Core|-lQt6Gui|-lQt6Network|-lQt6Test|-lQt6Widgets|-lq*) ;; \
              -lQt6*) \
                case " $$$$qt_libs " in *" $$$$token "*) ;; *) qt_libs="$$$$qt_libs $$$$token" ;; esac \
                ;; \
              -lzstd*|-lglib-*|-lgthread-*|-lgobject-*|-lgio-*|-lfreetype|-ljpeg) \
                echo "host Qt dependency leaked into Darwin metadata: $$$$token"; \
                exit 1 \
                ;; \
              -l*|-pthread) \
                case " $$$$qt_system_private " in *" $$$$token "*) ;; *) qt_system_private="$$$$qt_system_private $$$$token" ;; esac \
                ;; \
              *) \
                echo "unsupported Qt Darwin private linker token: $$$$token"; \
                exit 1 \
                ;; \
            esac; \
          done; \
        fi; \
      done; \
      if test -n "$$$$qt_expect_framework"; then \
        echo "incomplete Qt Darwin framework metadata"; \
        exit 1; \
      fi; \
      if test -z "$$$$qt_prl_found" || test -z "$$$$qt_system_private"; then \
        echo "missing Qt Darwin private link metadata"; \
        exit 1; \
      fi; \
      if test -z "$$$$qt_cocoa_resource_private"; then \
        echo "missing Qt Darwin Cocoa resource metadata"; \
        exit 1; \
      fi; \
      ;; \
    linux) \
      qt_requires_private="fontconfig freetype2 xcb xcb-shm xcb-render xcb-randr xcb-sync xcb-xfixes xcb-shape xcb-keysyms xcb-image xcb-renderutil xcb-icccm xcb-cursor xkbcommon xkbcommon-x11"; \
      qt_system_private="-lm -ldl -lpthread"; \
      ;; \
    mingw32) \
      qt_system_private="-lversion -lwinmm -lws2_32 -ldwmapi -limm32 -lole32 -loleaut32 -luuid -luxtheme -lgdi32 -luser32 -lshell32 -ladvapi32 -lsetupapi -lcomdlg32 -lshlwapi -lshcore -lcrypt32 -liphlpapi -lnetapi32 -lwtsapi32 -lwinspool -lbcrypt -ldnsapi -ldwrite -ld2d1 -ld3d9 -ld3d11 -ldxgi -lsynchronization -lauthz -luserenv -lruntimeobject -lsecur32 -lwinhttp"; \
      ;; \
  esac && \
  qt_private_libs="$$$$qt_link_group_open$$$$qt_object_private$$$$qt_plugin_libs$$$$qt_libs $$$$qt_link_group_close $$$$qt_system_private" && \
  write_qt_pc() { \
    module="$$$$1"; \
    libname="Qt6$$$$module"; \
    cflag="$$$$2"; \
    module_private_libs="$$$$qt_private_libs"; \
    if test "$(host_os)" = "darwin" && test "$$$$module" != "Core"; then \
      module_private_libs=; \
    fi; \
    { \
      printf 'prefix=%s\n' "$(host_prefix)"; \
      printf '%s\n' 'exec_prefix=$$$${prefix}'; \
      printf '%s\n' 'libdir=$$$${prefix}/lib'; \
      printf '%s\n' 'includedir=$$$${prefix}/include'; \
      printf 'host_bins=%s\n' "$$$$qt_host_bins"; \
      if test "$$$$module" = "Core" && test -n "$$$$qt_cocoa_resource_private"; then printf 'darwin_cocoa_resource_init=%s\n' "$$$$qt_cocoa_resource_private"; fi; \
      printf '\n'; \
      printf 'Name: Qt6 %s\n' "$$$$module"; \
      printf 'Description: Qt %s module for Nito depends static builds\n' "$$$$module"; \
      printf 'Version: %s\n' "$($(package)_version)"; \
      printf 'Libs: -L$$$${libdir} -l%s\n' "$$$$libname"; \
      printf 'Libs.private: %s\n' "$$$$module_private_libs"; \
      printf 'Cflags: -I$$$${includedir} -I$$$${includedir}/Qt%s %s\n' "$$$$module" "$$$$cflag"; \
      if test -n "$$$$qt_requires_private"; then printf 'Requires.private: %s\n' "$$$$qt_requires_private"; fi; \
    } > "lib/pkgconfig/$$$$libname.pc"; \
  } && \
  write_qt_pc Core -DQT_CORE_LIB && \
  write_qt_pc Gui -DQT_GUI_LIB && \
  write_qt_pc Widgets -DQT_WIDGETS_LIB && \
  write_qt_pc Network -DQT_NETWORK_LIB && \
  write_qt_pc Test -DQT_TESTLIB_LIB && \
  for pc in Qt6Core Qt6Gui Qt6Widgets Qt6Network Qt6Test; do \
    if ! test -s "lib/pkgconfig/$$$$pc.pc"; then \
      echo "missing generated Qt pkg-config file: $$$$pc.pc"; \
      exit 1; \
    fi; \
  done && \
  rm -rf lib/cmake lib/*.la && \
  if test -d bin; then rm -f bin/qmake bin/qtpaths; fi
endef
