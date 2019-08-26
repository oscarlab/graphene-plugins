#TO JUST PULL protected_fs directories from SGX SDK 

if [[ ! -d ./sdk ]] ; then
git init
git config core.sparseCheckout true
git remote add -f origin https://github.com/intel/linux-sgx
echo "sdk/protected_fs/*" > .git/info/sparse-checkout
# WARNING!! version of linux_sgx(i.e sgx_2.1.3) should
# match with the one on top of which sgx-protectedfs is patched-for
# in build_pfs_sdk.sh. Since both libraries(libfileops_interceptor.so
# and libpfs_sdk.a should refer to the same version of sgx header files during
# build and for compatibility.
# Except for some header files under sdk/protected_fs which have been
# modified with this patch.
git checkout sgx_2.1.3 -b changes_over_sdk_2.1.3

#TODO: Add check if (patch_file_exists) at the start of this script...
git am changes_on_sdk_2.1.3.patch  || exit 1
fi

#TODO: Add check for build errors and exit.
make -fMakefile_pfs_sdk clean  || exit 1
make -fMakefile_pfs_sdk all  || exit 1
