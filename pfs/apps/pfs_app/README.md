**Pre-requiste:**
Please refer to README.md at the top-level directory, to get an overview on Protected-Filesystem(PFS) shield library,
and the build and setup steps, before reading below.
For sake of brevity, this feature or library will hereon be referred to as PFS.

PFS library(libfileops_interceptor.so) will be used by pfs application, to transparently intercept filesystem I/O apis, and thereby
provide filesystem shield, and internally invoke apis in file protection feature from 
Intel's [SGX-SDK's Protected-FS](https://github.com/intel/linux-sgx/tree/master/sdk/protected_fs) library. 

**SETUP PRIOR TO RUNNING THE PROTFS_APP:**<br/>
**NOTE:** The application's manifest file(pfs_app.manifest.template), needs some modifications(as explained below), in order for it work as expected.<br/>

*  application's manifest should be set to point to the Runtime folder in graphene repo.<br/>
For example, in the example manifest file, path is->../../deps/graphene/Runtime, it needs to be changed as per user's path to graphene repo.<br/>
*  User needs to setup physical directory path(on user's system) to a mount-point, so graphene can mount(i.e. map) the physical <br/>
directory path to a virtual directory path in in its internal namespace.<br/>
Update below in the application manifest file(user needs to change as per user's setup):<br/>
Physical directory path is->/home/skris14/pfs_mount<br/>
Virtual directory path is ->/pfs_dir<br/>
*  Setting the overloaded PFS library:<br/>
*loader.env.LD_PRELOAD = libfileops_interceptor.so<br/>*
*  Mapping the physical directory path to virtual directory path in manifest:<br/>
Update below in the application manifest file(user needs to change as per user's setup):<br/>
*fs.mount.pfs.type = chroot<br/>
fs.mount.pfs.path = /pfs_dir<br/>
fs.mount.pfs.uri = file:/home/skris14/pfs_mount<br/>*
*  User needs to be setup the following directory structure under the physical directory path(like below):<br/>
cd to mount_point, and then run below:<br/>
mkdir -p test_dir secrets/sub_dir1 secrets/sub_dir2 non_secrets<br/>

After creating above sub-directories, doing ls at mount-point, should list below:<br/>
~/pfs_mount$ ls -ltr<br/>
test_dir<br/>
secrets<br/>
non_secrets<br/>
~/pfs_mount$ ls -ltr secrets/<br/>
sub_dir2<br/>
sub_dir1<br/>

* Setting root of protected directory(PFS_MOUNT_POINT): <br/>
**Note: PFS_MOUNT_POINT points to the top-level directory that can have protected files.**<br/>
Update below in the application manifest file(user needs to change as per user's setup):<br/>
loader.env.PFS_MOUNT_POINT = /pfs_dir/secrets<br/>*
Note that /pfs_dir is virtual directory-path. Physical directory-path has been mapped
to this virtual path in graphene's namespace, as explained earlier.
In this example, PFS_MOUNT_POINT happens to be a  sub-directory of the physical directory that has been mounted
and mapped to virtual directory path as per rules in graphene's manifest file.
* User needs to allow access to files under a given directory: <br/>
Update below in the application manifest file(user needs to change as per user's setup):<br/>
*sgx.allowed_files.mount_path = file:/home/skris14/pfs_mount<br/>*
**Note: In this example, we have allowed access to files in the parent directory 
of PFS_MOUNT_POINT. Reason being this application accesses some of the non-protected directories using the virtual directory path.**<br/>

* Setting file-protection key-type:<br/>
Set PFS_USE_CUSTOM_KEY, in application's manifest, to indicate whether PFS will be using custom key or autokey(i.e sealing key)<br/>
Update below in the application manifest file(user needs to change as per user's setup):<br/>
*loader.env.PFS_USE_CUSTOM_KEY = no<br/>*
If PFS_USE_CUSTOM_KEY is set to 'no' in application's manifest, PFS, will use SGX sealing key for protecting files.<br/>
Design doc under docs folder descibes how keys for filename encryption and other keys are derived from SGX sealing-key.<br/>
If PFS_USE_CUSTOM_KEY is set to 'yes' in application's manifest, this library(fops_interceptor.so), will expect a sealed_custom_key, in the current working directory<br/>
of the application.<br/>
***Note: High-level steps for how to generate sealed_custom_key file and process it is mentioned in README under the top-level directory.*<br/>***

**BUILDING AND RUNNING THE APP:**<br/>
1.  Option1: If PFS is already built, and just to build app and run<br/>
*./build_app.sh <br/>
./run_app.sh<br/>*
2. Option2: To re-build PFS library, and then build app and run<br/>
*./build_library_app_run.sh<br/>*

**PROTFS_APP DETAILS:**<br/>
    1. pfs_override_test(PATH_TO_PFS_TESTFILE) API: <br/>
    Creates and/or updates a file. Note that it just calls file-system apis, like fopen, fread and so on,
    but the overloaded PFS library(libfileops_interceptor.so), intercepts those calls, and depending on the path specified in the manifest, 
    it can either protect the file, by calling SGX SDK's protected-fs apis or route it to regular system call.<br/>
    2. protect_files(CLEAR_DIR_PATH, PROTECTED_DIR_PATH) API: <br/>
	This API can be used to take existing files in clear(non-encrypted) and output protected files.
	It expects path to directory that has clear files(CLEAR_DIR_PATH), and outputs protected files
	to protected directory(PROTECTED_DIR_PATH, which should be same as sub-directory of PFS_MOUNT_POINT
	in manifest).
	Additionally if CLEAR_DIR_PATH has sub-directories, it can replicate the sub-directories in
	PROTECTED_DIR_PATH. To summarise, it can recursively traverse the directory-tree under CLEAR_DIR_PATH
	and create sub-directories(if needed) in PROTECTED_DIR_PATH and output protected files.
