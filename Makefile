.PHONY: build, conan-setup, clean

OS := $(shell uname -s)
ifeq ($(OS),Linux)
	CONAN_COMPILER := clang
	CMAKE_CXX_COMPILER := clang++-13
else
	CONAN_COMPILER := apple-clang
	CMAKE_CXX_COMPILER := clang++
endif

build: conan-setup
	mkdir -p cmake-build-release
	cd cmake-build-release && CXX=$(CMAKE_CXX_COMPILER) conan install .. --profile=dyno_release --build=missing
	cd cmake-build-release && CXX=$(CMAKE_CXX_COMPILER) cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release
	cmake --build cmake-build-release

conan-setup:
	conan profile new dyno_release --detect || true
	conan profile update settings.compiler=$(CONAN_COMPILER) dyno_release
	conan profile update settings.compiler.version=13 dyno_release
	conan profile update settings.compiler.libcxx=libc++ dyno_release

clean:
	rm -rf cmake-build-release