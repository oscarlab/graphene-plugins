
cxx_srcs = $(patsubst %.cpp,%.cpp,$(wildcard *.cpp))

GRAPHENE_PATH = ../../deps/graphene
SHIMDIR = $(GRAPHENE_PATH)/LibOS/shim/src

$(info GRAPHENE_PATH is $(GRAPHENE_PATH))
$(info SHIMDIR is $(SHIMDIR))

#To enable verbose mode in GCC
CXXFLAGS +=-v
#To enable which headers it includes
#CXXFLAGS +=-H

PATH_TO_PFS_SDK_LIB=$(PATH_TO_PFS_ROOT)/pfs_sdk/

#TODO: Needs to be updated as needed
PATH_TO_PFS_ROOT=../../
PATH_TO_PFS_PROXY=$(PATH_TO_PFS_ROOT)/pfs_proxy
PATH_TO_PFS_PRELOAD=$(PATH_TO_PFS_ROOT)/ld_preload_lib
PFS_PROXY_OBJ_DIR=$(PATH_TO_PFS_ROOT)/pfs_proxy/obj
SGX_PROXY_INC=$(PATH_TO_PFS_PROXY)/sgx_proxy/inc
SGX_PROXY_SRC=$(PATH_TO_PFS_PROXY)/sgx_proxy/src

SDK_PROTECTFS=$(PATH_TO_PFS_ROOT)/pfs_sdk/sdk/protected_fs

SGX_GIT=$(PATH_TO_PFS_ROOT)/deps/linux-sgx
EPID_SDK=$(SGX_GIT)/external/epid-sdk-3.0.0

MBEDTLS=$(PATH_TO_PFS_ROOT)/deps/mbedtls
MBEDTLS_INC=$(MBEDTLS)/include
MBEDTLS_SRC=$(MBEDTLS)/library

SGX_SDK_INCLUDES += -I$(SGX_GIT)/common/inc/internal \
				-I$(EPID_SDK) -I$(SGX_GIT)/common/inc \
				-I/opt/intel/sgxsdk/include

CXXFLAGS += -fPIC -Wall -std=gnu++11 \
		-I$(SDK_PROTECTFS)/sgx_uprotected_fs/ \
		-I$(SDK_PROTECTFS)/sgx_tprotected_fs/ \
		-I$(PATH_TO_PFS_PROXY) \
		-I$(PATH_TO_PFS_PRELOAD) \
		-I$(SGX_PROXY_INC)
		
CXXFLAGS += $(SGX_SDK_INCLUDES)

CXXFLAGS += -I. -Ideps/local/include
#CFLAGSERRORS=-Werror -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow
CXXFLAGS += $(CFLAGSERRORS)# -DDEBUG -DDYNAMIC_RSA

#Note: Below flags needed only to test
#64 bit apis(explicitly like on 32-bit systems).
#On 64-bit systems, this conditional NOT needed.
#Enabling below conditional...replaces calls to 64-bit 
#equivalent apis..like readdir to readdir64.
#CXXFLAGS += -D_FILE_OFFSET_BITS=64

CFLAGS := $(filter-out -std=gnu++11,$(CXXFLAGS))

CFLAGS += -std=gnu99


CFLAGS += -I$(MBEDTLS_INC)

$(info CXXFLAGS is $(CXXFLAGS))
$(info CFLAGS is $(CFLAGS))
$(info PFS_PROXY_OBJ_DIR is $(PFS_PROXY_OBJ_DIR))

#For debugging symbols.
CXXFLAGS +=-g

CXXFLAGS += -I$(SHIMDIR)/../../../Pal/src/host/Linux-SGX/ \
		-I$(SHIMDIR)/../../../Pal/include/pal \
		-I$(MBEDTLS_INC) 
		#-I$(SHIMDIR)/../../../Pal/lib/crypto/mbedtls/mbedtls/

$(info CXXFLAGS is $(CXXFLAGS))


pfs_app:
	$(info cxx_srcs is $(cxx_srcs))
	g++ -o pfs_app $(cxx_srcs) $(CXXFLAGS) -L$(PATH_TO_PFS_PROXY) -L$(MBEDTLS_SRC) -L$(PATH_TO_PFS_SDK_LIB) -lpfs_proxy -lpfs_sdk -lmbedtls_crypto -ldl
	$(GRAPHENE_PATH)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal $(GRAPHENE_PATH)/Runtime/libpal-Linux-SGX.so -key $(GRAPHENE_PATH)/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -exec $@ -manifest pfs_app.manifest.template
	$(GRAPHENE_PATH)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig

#mbedtls-ssl-server : $(MBEDTLS_SSL_SERVER_SRC) ssl-server.manifest deps/graphene/Runtime/pal_loader
#	$(CC) $(MBEDTLS_SSL_SERVER_SRC) -o $@ $(CFLAGSERRORS) $(SSL_SERVER_INCLUDES) -Ldeps/local/lib/ $(MBEDTLS_SSL_SERVER_LIBS)
#	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign -libpal deps/graphene/Runtime/libpal-Linux-SGX.so -key deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem -output $@.manifest.sgx -#exec $@ -manifest ssl-server.manifest
#	deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@.token -sig $@.sig


.PHONY: format
format:
	clang-format -i $(shell find . \( -name '*.h' -o -name '*.cpp' -o -name '*.c' \) -print)

all: pfs_app

clean: 
	$(RM) pfs_app pfs_app.token pfs_app.sig pfs_app.manifest.sgx
