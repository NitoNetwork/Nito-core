package=native_qt
$(package)_version=6.8.4
$(package)_download_path=https://download.qt.io/archive/qt/6.8/$($(package)_version)/single
$(package)_fallback_download_path=https://ftp.fau.de/qtproject/archive/qt/6.8/$($(package)_version)/single
$(package)_file_name=qt-everywhere-opensource-src-$($(package)_version).tar.xz
$(package)_sha256_hash=1da37a32a583e7856d6fc13357c8ff6ad3ef7b877b8d276713b85026426d5246
$(package)_patches=qhttpheaders_compare_views.patch CVE-2026-78253.patch CVE-2026-76151.patch CVE-2026-19248.patch
ifeq ($(build_os),darwin)
$(package)_patches+=qttools_clang_feature_guards.patch qml_explicit_type_name_utf8.patch
$(package)_submodules=qtbase,qttools
else
$(package)_submodules=qtbase
endif
define $(package)_set_vars
$(package)_config_opts_release = -release
$(package)_config_opts_debug = -debug
$(package)_config_opts += -opensource
$(package)_config_opts += -confirm-license
$(package)_config_opts += -prefix $(build_prefix)/qt-host/qtbase
$(package)_config_opts += -cmake-generator Ninja
$(package)_config_opts += -nomake examples
$(package)_config_opts += -nomake tests
$(package)_config_opts += -no-dbus
$(package)_config_opts += -no-opengl
$(package)_config_opts += -no-openssl
$(package)_config_opts += -no-feature-printsupport
$(package)_config_opts += -no-feature-sql
$(package)_config_opts += -qt-harfbuzz
$(package)_config_opts += -qt-libpng
$(package)_config_opts += -qt-pcre
$(package)_config_opts += -qt-zlib
$(package)_config_opts += -submodules $($(package)_submodules)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-framework)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-assistant)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-designer)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-distancefieldgenerator)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-pixeltool)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-qdoc)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-qtattributionsscanner)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-qtdiag)
$(package)_config_opts += $(if $(filter darwin,$(build_os)),-no-feature-qtplugininfo)
$(package)_cmake_opts += -DQT_BUILD_EXAMPLES_BY_DEFAULT=OFF
$(package)_cmake_opts += -DQT_BUILD_TESTS_BY_DEFAULT=OFF
$(package)_cmake_opts += $(if $(filter darwin,$(build_os)),-DFEATURE_clang=OFF)
$(package)_cmake_opts += $(if $(filter darwin,$(build_os)),-DFEATURE_clangcpp=OFF)
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/qhttpheaders_compare_views.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-78253.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-76151.patch && \
  patch -p1 < $($(package)_patch_dir)/CVE-2026-19248.patch && \
  if test "$(build_os)" = "darwin"; then \
    patch -p1 < $($(package)_patch_dir)/qttools_clang_feature_guards.patch && \
    patch -p1 < $($(package)_patch_dir)/qml_explicit_type_name_utf8.patch; \
  fi
endef

define $(package)_config_cmds
  ./configure $($(package)_config_opts) -- $($(package)_cmake_opts)
endef

# The Darwin host_tools aggregate also builds unrelated Cocoa and QML tools.
# Build and stage the exact host-tool set consumed by the target Qt build.
define $(package)_build_cmds
  if test "$(build_os)" = "darwin"; then \
    cmake --build . --parallel $(if $(JOBS),$(JOBS),1) --target \
      syncqt moc rcc tracepointgen tracegen cmake_automoc_parser qlalr \
      qmake qtpaths macdeployqt qvkgen uic lconvert lrelease lupdate; \
  else \
    cmake --build . --parallel $(if $(JOBS),$(JOBS),1) --target host_tools; \
  fi
endef

define $(package)_stage_cmds
  if test "$(build_os)" = "darwin"; then \
    mkdir -p \
      $($(package)_staging_prefix_dir)/qt-host/qtbase/bin \
      $($(package)_staging_prefix_dir)/qt-host/qtbase/libexec; \
    for dir in bin libexec; do \
      if test -d "qtbase/$$$$dir"; then \
        for tool in qtbase/$$$$dir/*; do \
          if test -f "$$$$tool" && test -x "$$$$tool"; then \
            cp "$$$$tool" "$($(package)_staging_prefix_dir)/qt-host/qtbase/$$$$dir/"; \
          fi; \
        done; \
      fi; \
    done; \
  else \
    DESTDIR=$($(package)_staging_dir) cmake --install . --component host_tools; \
  fi && \
  mkdir -p \
    $($(package)_staging_prefix_dir)/bin \
    $($(package)_staging_prefix_dir)/qt-host/qtbase/bin \
    $($(package)_staging_prefix_dir)/qt-host/qtbase/libexec \
    $($(package)_staging_prefix_dir)/qt-host/qtbase/lib \
    $($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake && \
  if test "$(build_os)" = "darwin" && \
     ! test -x "$($(package)_staging_prefix_dir)/qt-host/qtbase/bin/lrelease"; then \
    echo "missing pinned native Qt lrelease"; \
    exit 1; \
  fi && \
  if ! test -d qtbase/lib/cmake/Qt6HostInfo; then \
    echo "missing native Qt HostInfo package"; \
    exit 1; \
  fi && \
  cp -a qtbase/lib/cmake/Qt6HostInfo "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake/" && \
  for pkg in Qt6CoreTools Qt6GuiTools Qt6WidgetsTools; do \
    case "$$$$pkg" in \
      Qt6CoreTools) \
        tools="syncqt moc rcc tracepointgen tracegen cmake_automoc_parser qlalr qmake qtpaths"; \
        if test "$(build_os)" = "darwin"; then tools="$$$$tools macdeployqt"; fi \
        ;; \
      Qt6GuiTools) tools="qvkgen" ;; \
      Qt6WidgetsTools) tools="uic" ;; \
    esac; \
    pkgdir="$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake/$$$$pkg"; \
    mkdir -p "$$$$pkgdir"; \
    { \
      printf 'set(%s_FOUND TRUE)\n' "$$$$pkg"; \
      printf 'if(NOT QT_NO_CREATE_TARGETS AND %s_FOUND)\n' "$$$$pkg"; \
      printf '  include("$$$${CMAKE_CURRENT_LIST_DIR}/%sTargets.cmake")\n' "$$$$pkg"; \
      printf '  include("$$$${CMAKE_CURRENT_LIST_DIR}/%sAdditionalTargetInfo.cmake" OPTIONAL)\n' "$$$$pkg"; \
      printf '  if(NOT QT_NO_CREATE_VERSIONLESS_TARGETS)\n'; \
      printf '    include("$$$${CMAKE_CURRENT_LIST_DIR}/%sVersionlessTargets.cmake" OPTIONAL)\n' "$$$$pkg"; \
      printf '  endif()\n'; \
      printf 'endif()\n'; \
    } > "$$$$pkgdir/$$$${pkg}Config.cmake"; \
    printf '%s\n' \
      'set(PACKAGE_VERSION "$($(package)_version)")' \
      'if(PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION)' \
      '  set(PACKAGE_VERSION_COMPATIBLE FALSE)' \
      'else()' \
      '  set(PACKAGE_VERSION_COMPATIBLE TRUE)' \
      '  if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)' \
      '    set(PACKAGE_VERSION_EXACT TRUE)' \
      '  endif()' \
      'endif()' \
      > "$$$$pkgdir/$$$${pkg}ConfigVersion.cmake"; \
    { \
      printf '%s\n' \
        'get_filename_component(_qt6_host_tools_prefix "$$$${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)' \
        'set(_qt6_host_tools_bin "$$$${_qt6_host_tools_prefix}/bin")' \
        'set(_qt6_host_tools_libexec "$$$${_qt6_host_tools_prefix}/libexec")' \
        'function(_nito_qt6_import_tool target_name executable_name)' \
        '  set(_nito_qt6_tool_location "")' \
        '  foreach(_nito_qt6_tool_dir "$$$${_qt6_host_tools_libexec}" "$$$${_qt6_host_tools_bin}")' \
        '    if(EXISTS "$$$${_nito_qt6_tool_dir}/$$$${executable_name}")' \
        '      set(_nito_qt6_tool_location "$$$${_nito_qt6_tool_dir}/$$$${executable_name}")' \
        '      break()' \
        '    endif()' \
        '  endforeach()' \
        '  if(NOT _nito_qt6_tool_location)' \
        '    set(_nito_qt6_tool_location "$$$${_qt6_host_tools_libexec}/$$$${executable_name}")' \
        '  endif()' \
        '  if(NOT TARGET Qt6::$$$${target_name})' \
        '    add_executable(Qt6::$$$${target_name} IMPORTED GLOBAL)' \
        '  endif()' \
        '  set_target_properties(Qt6::$$$${target_name} PROPERTIES IMPORTED_LOCATION "$$$${_nito_qt6_tool_location}")' \
        '  if(NOT TARGET Qt::$$$${target_name})' \
        '    add_executable(Qt::$$$${target_name} IMPORTED GLOBAL)' \
        '  endif()' \
        '  set_target_properties(Qt::$$$${target_name} PROPERTIES IMPORTED_LOCATION "$$$${_nito_qt6_tool_location}")' \
        'endfunction()'; \
      printf 'set(%s_TARGETS "")\n' "$$$$pkg"; \
    } > "$$$$pkgdir/$$$${pkg}Targets.cmake"; \
    for tool in $$$$tools; do \
      printf '_nito_qt6_import_tool(%s %s)\n' "$$$$tool" "$$$$tool" >> "$$$$pkgdir/$$$${pkg}Targets.cmake"; \
      printf 'list(APPEND %s_TARGETS Qt6::%s)\n' "$$$$pkg" "$$$$tool" >> "$$$$pkgdir/$$$${pkg}Targets.cmake"; \
    done; \
    : > "$$$$pkgdir/$$$${pkg}AdditionalTargetInfo.cmake"; \
    : > "$$$$pkgdir/$$$${pkg}VersionlessTargets.cmake"; \
  done && \
  if test -d qtbase/lib; then \
    cp -P qtbase/lib/libQt6*.so* "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/" 2>/dev/null || true; \
    cp -P qtbase/lib/libQt6*.dylib* "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/" 2>/dev/null || true; \
  fi && \
  for pkg in Qt6HostInfo Qt6CoreTools Qt6GuiTools Qt6WidgetsTools; do \
    if ! test -d "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake/$$$$pkg"; then \
      echo "missing native Qt CMake package: $$$$pkg"; \
      exit 1; \
    fi; \
  done && \
  if ! test -f "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake/Qt6HostInfo/Qt6HostInfoConfig.cmake"; then \
    echo "missing native Qt HostInfo config"; \
    exit 1; \
  fi && \
  for pkg in Qt6CoreTools Qt6GuiTools Qt6WidgetsTools; do \
    for file in $$$${pkg}Config.cmake $$$${pkg}Targets.cmake; do \
      if ! test -f "$($(package)_staging_prefix_dir)/qt-host/qtbase/lib/cmake/$$$$pkg/$$$$file"; then \
        echo "missing native Qt CMake file: $$$$pkg/$$$$file"; \
        exit 1; \
      fi; \
    done; \
  done && \
  for tool in $($(package)_staging_prefix_dir)/qt-host/qtbase/bin/* $($(package)_staging_prefix_dir)/qt-host/qtbase/libexec/*; do \
    if test -f "$$$$tool" && test -x "$$$$tool"; then \
      name=$$$${tool##*/}; \
      printf '%s\n' \
        '#!/usr/bin/env sh' \
        'case "$$$$0" in */*) script="$$$$0";; *) script=$$$$(command -v -- "$$$$0");; esac' \
        'qt_host_dir="$$$${script%/*}/../qt-host/qtbase"' \
        'export LD_LIBRARY_PATH="$$$$qt_host_dir/lib$$$${LD_LIBRARY_PATH:+:$$$$LD_LIBRARY_PATH}"' \
        'export DYLD_LIBRARY_PATH="$$$$qt_host_dir/lib$$$${DYLD_LIBRARY_PATH:+:$$$$DYLD_LIBRARY_PATH}"' \
        'if test -x "$$$$qt_host_dir/libexec/'"$$$$name"'"; then exec "$$$$qt_host_dir/libexec/'"$$$$name"'" "$$$$@"; fi' \
        'exec "$$$$qt_host_dir/bin/'"$$$$name"'" "$$$$@"' \
        > "$($(package)_staging_prefix_dir)/bin/$$$$name"; \
      chmod +x "$($(package)_staging_prefix_dir)/bin/$$$$name"; \
    fi; \
  done && \
  required_tools="moc rcc uic qmake qtpaths" && \
  if test "$(build_os)" = "darwin"; then \
    required_tools="syncqt moc rcc tracepointgen tracegen cmake_automoc_parser qlalr qmake qtpaths macdeployqt qvkgen uic lconvert lrelease lupdate"; \
  fi && \
  for tool in $$$$required_tools; do \
    if ! test -x "$($(package)_staging_prefix_dir)/bin/$$$$tool"; then \
      echo "missing staged native Qt tool: $$$$tool"; \
      exit 1; \
    fi; \
  done && \
  if test "$(build_os)" = "darwin" && \
     ! "$($(package)_staging_prefix_dir)/bin/lrelease" -version; then \
    echo "staged native Qt lrelease cannot execute"; \
    exit 1; \
  fi
endef

define $(package)_postprocess_cmds
  rm -rf qt-host/qtbase/doc qt-host/qtbase/examples qt-host/qtbase/tests
endef
