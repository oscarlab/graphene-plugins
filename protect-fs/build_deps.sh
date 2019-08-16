#!/bin/bash

#set -x

DEFAULT_GRAPHENE_PATH=./deps/graphene
install_graphene=0

check_for_graphene_install()
{
	while true
	do
	echo "If you dont have graphene installed, this script will install graphene under default directory-path->"$DEFAULT_GRAPHENE_PATH
	echo -n "Do you already have graphene installed in a non-default location? [yes/no] : "
	read ANSWER

	if [ "$ANSWER" == "yes" ]; then
		install_graphene=0
		break
	elif [ "$ANSWER" == "no" ]; then
		install_graphene=1
		break
	else
		echo "you replied="$ANSWER", please type yes or no"
	fi
	done

	echo "install_graphene var set to= "$install_graphene

}

if [[ ! -d $DEFAULT_GRAPHENE_PATH ]] ; then
	check_for_graphene_install
else
	echo "graphene already setup in default path->"$DEFAULT_GRAPHENE_PATH
fi

# You need the SGX SDK and PSW installed.

mkdir -p deps
pushd deps

if [ ! -d mbedtls ] ; then
    git clone https://github.com/ARMmbed/mbedtls.git
    pushd mbedtls
    git checkout mbedtls-2.16.2
    patch -p1 < ../../mbedtls_config_file_aesni.patch || exit 1
    popd
fi

# Linux SGX SDK code
# WARNING!! version of linux_sgx(i.e sgx_2.1.3) should
# match with the one on top of which sgx-protectedfs is patched-for
# in build_pfs_sdk.sh. Since both libraries(libfileops_interceptor.so
# and libpfs_sdk.a should refer to the same version of sgx header files during
# build and for compatibility.
# Except for some header files under sdk/protected_fs which have been
# modified with this patch.
if [[ ! -d linux-sgx ]] ; then
    git clone https://github.com/01org/linux-sgx.git
    pushd linux-sgx
    git checkout sgx_2.1.3
    popd
fi

#After installing dependencies, we can 
#build sources in pfs_sdk directory, outside of deps directory.
popd
if [[ -d pfs_sdk ]] ; then
	pushd pfs_sdk
	./build_pfs_sdk.sh || exit 1
	popd
fi
pushd deps

if [[ ! -d linux-sgx-driver ]] ; then
     git clone https://github.com/01org/linux-sgx-driver.git
     pushd linux-sgx-driver
     git checkout sgx_driver_2.0
     popd
fi


if [[ ! -d $DEFAULT_GRAPHENE_PATH && $install_graphene -eq 1 ]] ; then
    git clone --recursive https://github.com/oscarlab/graphene.git
    pushd graphene
	#Note: below graphene commit works fine.
	git checkout aa9743dbcedeffe26ed71debeb07fe7ca4231bd7
    openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072
    # patch -p1 < ../../graphene-sgx-linux-driver-2.1.patch
    # The Graphene build process requires two inputs: (i) SGX driver directory, (ii) driver version.
    # cannot use make -j`nproc` with Graphene's build process.
    printf "$(readlink -f ../linux-sgx-driver)\n2.0\n" | make SGX=1 || exit 1

    # reduces the effort in the Graphene-SGX manifest file.
    ln -s /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 Runtime/
    ln -s /usr/lib/libsgx_uae_service.so Runtime/
    ln -s /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 Runtime/
    ln -s /lib/x86_64-linux-gnu/libz.so.1 Runtime/
    ln -s /lib/x86_64-linux-gnu/libssl.so.1.0.0 Runtime/
   
    popd
fi

popd # deps
