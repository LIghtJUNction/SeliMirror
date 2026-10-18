# SPDX-License-Identifier: GPL-2.0-only
PYTHON ?= python3
HOSTCC ?= cc
KERNEL_SRC ?= third_party/android_kernel_xiaomi_sm8150
KERNEL_OUT ?= third_party/kernel-out
BUILD_DIR ?= build
DIST_DIR ?= dist

.PHONY: all build check test test-gateway test-module test-rskctl clean
all: build

build:
	$(PYTHON) tools/build.py --kernel "$(KERNEL_SRC)" --kernel-out "$(KERNEL_OUT)" --build-dir "$(BUILD_DIR)" --dist "$(DIST_DIR)" $(if $(ZIG),--zig "$(ZIG)",$(if $(KPM_CC),--cc "$(KPM_CC)",) $(if $(KPM_LD),--ld "$(KPM_LD)",))

check:
	$(PYTHON) tools/check_kpm.py "$(DIST_DIR)/selimirror.kpm"

test:
	mkdir -p "$(BUILD_DIR)"
	$(HOSTCC) -std=c11 -O1 -g -Wall -Wextra -Werror -DRSK_HOST_TEST -Iinclude -fsanitize=address,undefined -fno-omit-frame-pointer src/core.c tests/test_core.c -o "$(BUILD_DIR)/test-core"
	"$(BUILD_DIR)/test-core"

test-gateway:
	$(PYTHON) tests/test_gateway.py --object "$(BUILD_DIR)/gateway_asm.o" -v

test-module:
	$(PYTHON) tests/test_module.py --module "$(DIST_DIR)/selimirror.kpm" -v

test-rskctl:
	$(PYTHON) tests/test_rskctl.py --binary "$(DIST_DIR)/rskctl"

clean:
	$(PYTHON) -c 'import pathlib, shutil; [shutil.rmtree(p) for p in (pathlib.Path("build"), pathlib.Path("dist")) if p.is_dir()]'
