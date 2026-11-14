package=native_meson
$(package)_version=1.11.2
$(package)_download_path=https://github.com/mesonbuild/meson/releases/download/$($(package)_version)
$(package)_fallback_download_path=https://files.pythonhosted.org/packages/source/m/meson
$(package)_file_name=meson-$($(package)_version).tar.gz
$(package)_sha256_hash=698feae069cef3ecd4d7aaf281d7df359bdfcf555a9a1564383d3b913fa8a736

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/bin $($(package)_staging_prefix_dir)/libexec/meson && \
  cp -R meson.py mesonbuild $($(package)_staging_prefix_dir)/libexec/meson/ && \
  printf '%s\n' '#!/usr/bin/env sh' \
    'exec python3 "$$$$(dirname "$$$$0")/../libexec/meson/meson.py" "$$$$@"' \
    > $($(package)_staging_prefix_dir)/bin/meson && \
  chmod 0755 $($(package)_staging_prefix_dir)/bin/meson
endef
