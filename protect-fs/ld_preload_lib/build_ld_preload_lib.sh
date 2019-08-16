set -x

file=fops_interceptor.c

echo "About to build shared libarary using file" $file
filename=$(basename -- "$file")
filename="${filename%.*}"

echo "filename"=$filename

protfs_path=../protected_fs

g++ -g -std=c++11 -shared -fPIC -I$protfs_path/sgx_tprotected_fs -I$protfs_path/ \
		-I$protfs_path/sgx_uprotected_fs -I$protfs_path/sgx_proxy \
	$filename.c -o $filename.so -L$protfs_path/obj -L$protfs_path/mbedtls_crypto_lib -lprotected_fs -lmbedtls_crypto -ldl

cp $filename.so ../../Runtime
