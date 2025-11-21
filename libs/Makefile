#!/usr/bin/make

CC := musl-gcc

.DEFAULT_GOAL: all
all: mbedtls4

mbedtls4:
	@if [ ! -d $@ ]; then \
		wget -O ./mbedtls.tar.bz2 \
			"https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.0.0/mbedtls-4.0.0.tar.bz2"; \
		tar -vxjf ./mbedtls.tar.bz2 -C .; \
		rm ./mbedtls.tar.bz2; \
		mv ./mbedtls-4.0.0 $@; \
		cd $@; \
		patch -p1 < ../patches/mbedtls4/arm64-build.patch; \
	fi
	@if [ ! -d $@/build ]; then \
		mkdir -p $@/build; \
		cd $@/build; \
		CC=$(CC) cmake \
			-DCMAKE_BUILD_TYPE=MinSizeRel \
		  -DCMAKE_C_FLAGS="-Os -ffunction-sections -fdata-sections" \
			-DENABLE_TESTING=OFF \
			-DENABLE_PROGRAMS=OFF \
			-DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
			.. \
		&& cmake --build . --target lib -j$(shell nproc); \
	fi

.PHONY: clean
clean:
	-rm -r ./mbedtls4
