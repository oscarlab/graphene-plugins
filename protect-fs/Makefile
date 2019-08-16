#To enable verbose mode in GCC
#CXXFLAGS +=-v
#To enable which headers it includes
#CXXFLAGS +=-H

CFLAGS_ASSEMBLY =-DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp -DIN_ENCLAVE

#Note: as part of build_deps.sh script, this libpfs_sdk.a, should already be built.
PATH_TO_PFS_SDK_LIB=./pfs_sdk/

DEPS_GRAPHENE=./deps/graphene
DEPS_MBEDTLS=./deps/mbedtls
DEPS_LINUX_SGX=./deps/linux-sgx

#Note: 
#By default build script, sets up graphene in this path-> ./deps/graphene
# Path variable DEPS_GRAPHENE can be updated(if needed),
#in a file->custom_makefile_variables,
# so that library(/libfileops_interceptor.so) will get 
#copied to user's graphene repo's Runtime directory path.
# Add rule below in file->custom_makefile_variables, if path needs to be updated.
#DEPS_GRAPHENE=/path_to_graphene_repo_directory_path/
-include ./custom_makefile_variables

$(info DEPS_GRAPHENE is $(DEPS_GRAPHENE))

PATH_TO_GPFS_ROOT=./
PATH_TO_PROTFS_PROXY=$(PATH_TO_GPFS_ROOT)/pfs_proxy
PATH_TO_GPFS_PRELOAD=$(PATH_TO_GPFS_ROOT)/ld_preload_lib
PROTFS_PROXY_OBJ_DIR=$(PATH_TO_GPFS_ROOT)/pfs_proxy/obj
SGX_PROXY_INC=$(PATH_TO_PROTFS_PROXY)/sgx_proxy/inc
SGX_PROXY_SRC=$(PATH_TO_PROTFS_PROXY)/sgx_proxy/src

SDK_PROTECTFS=$(PATH_TO_GPFS_ROOT)/pfs_sdk/sdk/protected_fs

#Related to linux_sgx
EPID_SDK=$(DEPS_LINUX_SGX)/external/epid-sdk-3.0.0

SGX_SDK_INCLUDES += -I$(DEPS_LINUX_SGX)/common/inc/internal \
				-I$(EPID_SDK) -I$(DEPS_LINUX_SGX)/common/inc \
				-I/opt/intel/sgxsdk/include \
				-I$(DEPS_LINUX_SGX)//sdk/trts/ \
				-I$(DEPS_LINUX_SGX)//sdk/trts/linux

CXXFLAGS += -fPIC -Wall -std=gnu++11 \
		-I$(SDK_PROTECTFS)/sgx_uprotected_fs/ \
		-I$(SDK_PROTECTFS)/sgx_tprotected_fs/ \
		-I$(PATH_TO_PROTFS_PROXY) \
		-I$(PATH_TO_GPFS_PRELOAD) \
		-I$(SGX_PROXY_INC)
		
CXXFLAGS += $(SGX_SDK_INCLUDES)

#Related to mbedtls
MBEDTLS_INC=$(DEPS_MBEDTLS)/include
MBEDTLS_SRC=$(DEPS_MBEDTLS)/library

CXXFLAGS += -I$(MBEDTLS_INC)

#CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
#Note: Enable Werror to get rid of warnings...
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow
CXXFLAGS += $(CFLAGSERRORS)# -DDEBUG -DDYNAMIC_RSA

CFLAGS := $(filter-out -std=gnu++11,$(CXXFLAGS))

CFLAGS += -std=gnu99

$(info CXXFLAGS is $(CXXFLAGS))
$(info CFLAGS is $(CFLAGS))
$(info PROTFS_PROXY_OBJ_DIR is $(PROTFS_PROXY_OBJ_DIR))
$(info CXX is $(CXX))
$(info CC is $(CC))

#Using makefile's implicit rules to compile *.c files into *.o object files, using CFLAGS.
#https://www.gnu.org/software/make/manual/html_node/Implicit-Variables.html
MBEDTLS_CRYPTO_OBJS := $(MBEDTLS_SRC)/gcm.o $(MBEDTLS_SRC)/aes.o $(MBEDTLS_SRC)/cmac.o \
					$(MBEDTLS_SRC)/cipher.o $(MBEDTLS_SRC)/cipher_wrap.o $(MBEDTLS_SRC)/aesni.o \
					$(MBEDTLS_SRC)/ccm.o $(MBEDTLS_SRC)/sha256.o $(MBEDTLS_SRC)/md.o \
					$(MBEDTLS_SRC)/md_wrap.o $(MBEDTLS_SRC)/md5.o $(MBEDTLS_SRC)/sha1.o \
					$(MBEDTLS_SRC)/ripemd160.o $(MBEDTLS_SRC)/sha512.o $(MBEDTLS_SRC)/platform_util.o

$(MBEDTLS_SRC)/libmbedtls_crypto.a: $(MBEDTLS_CRYPTO_OBJS)
	$(AR) rcs $@ $^

PROTFS_SGX_PROXY_SRC_FILES := $(wildcard $(SGX_PROXY_SRC)/*.cpp)
PROTFS_SGX_PROXY_OBJ_FILES := $(patsubst $(SGX_PROXY_SRC)/%.cpp,$(PROTFS_PROXY_OBJ_DIR)/%.o,$(PROTFS_SGX_PROXY_SRC_FILES))

$(PROTFS_PROXY_OBJ_DIR)/%.o: $(SGX_PROXY_SRC)/%.cpp
	mkdir -p $(PROTFS_PROXY_OBJ_DIR)
	g++ -c $(CXXFLAGS) $< -o $@

PROTFS_SRC_FILES := $(wildcard $(PATH_TO_PROTFS_PROXY)/*.cpp)
PROTFS_OBJ_FILES := $(patsubst $(PATH_TO_PROTFS_PROXY)/%.cpp,$(PROTFS_PROXY_OBJ_DIR)/%.o,$(PROTFS_SRC_FILES))

$(PROTFS_PROXY_OBJ_DIR)/%.o: $(PATH_TO_PROTFS_PROXY)/%.cpp
	g++ -c $(CXXFLAGS) $< -o $@

PROTFS_ASSEMBLY_SRC_FILES := $(wildcard $(SGX_PROXY_SRC)/*.S)
PROTFS_ASSEMBLY_OBJ_FILES := $(patsubst $(SGX_PROXY_SRC)/%.S,$(PROTFS_PROXY_OBJ_DIR)/%.o,$(PROTFS_ASSEMBLY_SRC_FILES))

CFLAGS_ASSEMBLY += $(SGX_SDK_INCLUDES)

$(PROTFS_PROXY_OBJ_DIR)/%.o: $(SGX_PROXY_SRC)/%.S
		gcc -c $(CFLAGS_ASSEMBLY) $^ -o $@

$(PATH_TO_PROTFS_PROXY)/libprotected_fs_proxy.a: $(PROTFS_SGX_PROXY_OBJ_FILES) \
			$(PROTFS_OBJ_FILES) $(PROTFS_ASSEMBLY_OBJ_FILES) -ldl
	$(AR) rcs $@ $^

$(PATH_TO_PFS_SDK_LIB)/libsdk_pfs.a:
	cd $(PATH_TO_PFS_SDK_LIB) && make -fMakefile_PFS_SDK all

FILEOPS_INTERCEPTOR_FILES := $(wildcard $(PATH_TO_GPFS_PRELOAD)/*.c)
$(info FILEOPS_INTERCEPTOR_FILES is $(FILEOPS_INTERCEPTOR_FILES))

$(PATH_TO_GPFS_PRELOAD)/libfileops_interceptor.so : $(FILEOPS_INTERCEPTOR_FILES) $(PATH_TO_PROTFS_PROXY)/libprotected_fs_proxy.a $(MBEDTLS_SRC)/libmbedtls_crypto.a $(PATH_TO_PFS_SDK_LIB)/libsdk_pfs.a
	g++ -o $@ $^ -g -std=c++11 -shared -fPIC $(CXXFLAGS) -L$(PATH_TO_PROTFS_PROXY) -L$(MBEDTLS_SRC) -L$(PATH_TO_PFS_SDK_LIB) -lprotected_fs_proxy -lsdk_pfs -lmbedtls_crypto -ldl
	cp $@ $(DEPS_GRAPHENE)/Runtime

README.html : README.md
	pandoc --from markdown_github --to html --standalone $< --output $@

clean:
#Not cleaning external libraries(that we dont modify) under 
#/deps/ in build_deps.sh.
	rm -rf ./ld_preload_lib/libfileops_interceptor.so
	rm -rf ./pfs_proxy/libprotected_fs_proxy.a
	rm -rf $(MBEDTLS_SRC)/libmbedtls_crypto.a $(MBEDTLS_SRC)/*.o
	rm -rf $(SDK_PROTECTFS)/obj;
	cd $(PATH_TO_PFS_SDK_LIB) && make -fMakefile_PFS_SDK clean

all: format $(PATH_TO_GPFS_PRELOAD)/libfileops_interceptor.so

.PHONY: format
format:
	clang-format -i $(shell find .  -path ./deps -prune -o \
					-path ./pfs_sdk -prune -o \
					\( -name '*.h' -o -name '*.cpp' -o -name '*.c' \) -print)
	#clang-format -i $(shell find ./pfs_sdk/sdk/protected_fs \
	#				\( -name '*.h' -o -name '*.cpp' -o -name '*.c' \) -print)

mrproper: clean
	$(RM) -r deps/graphene deps/linux-sgx deps/linux-sgx-driver
	$(RM) -r deps/mbedtls
	rm -rf ./pfs_sdk/.git
	rm -rf ./pfs_sdk/sdk

#.PHONY = all mrproper
