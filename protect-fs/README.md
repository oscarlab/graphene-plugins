**Graphene-ProtectedFileSystem shield(GPFS) library:**

These sources produce a library, that provides file-system shield to [Graphene](https://github.com/oscarlab/graphene), by incorporating file protection feature from<br/>
Intel's [SGX-SDK's Protected-FS library](https://github.com/intel/linux-sgx/tree/master/sdk/protected_fs).<br/>
For sake of brevity, this feature or library will hereon be referred to as GPFS.<br/>

**ASSUMPTION/PRE-REQUISTE:**
* User of this GPFS library, is expected to be familiar with [Graphene-SGX](https://github.com/oscarlab/graphene/wiki/Introduction-to-Intel-SGX-Support).<br/>
* User uses this GPFS library, with Intel SGX enabled in Graphene.<br/>
* User is also expected to be familiar with building applications using Graphene.<br/>
* This GPFS library will reside as an optional plugin at the top-level directory in Graphene repo.<br/>
* User has familiarity with Intel's [SGX feature sources](https://github.com/intel/linux-sgx)<br/>
* User has familiarity with Intel [SGX SDK's Protect-FS feature](https://software.intel.com/en-us/articles/overview-of-intel-protected-file-system-library-using-software-guard-extensions)

**DETAILED OVERVIEW:**
Integrated [SGX SDK's Protected-FS](https://github.com/intel/linux-sgx/tree/master/sdk/protected_fs) library WITHOUT sgx-sdk dependencies, as a library that can be linked by unmodified
applications in [Graphene](https://github.com/oscarlab/graphene)\
*Note: Sgx-sdk dependencies for crypto, getting EREPORT, EGETKEY, have been substituted by taking some of the related 
code from SGX-SDK, and packaging as part of this GPFS library*

Overloaded library called as libfileops_interceptor.so(i.e GPFS library), has been added,which can route the file-related C api calls to corresponding api in Protected-FS library\
(OR) regular file-system api\
*Graphene application’s manfiest file, specifies the path to directory where protected files reside.<br/>*
For "List of Filesystem apis handled (and the ones not handled) by library", please refer to section below in README: <br/>

Using the overloaded library(libfileops_interceptor.so), we are able to transparently intercept file-system api calls<br/>
from unmodified application, and provide cryptographic protection mechanism(using SGX-ProtectedFS library).<br/>
<br/>
Files to be protected are mounted on pre-defined directory-path specified in graphene application's manifest.<br/>
With SGX-SDK's ProtectedFS mentioned above we only get confidentiality and integrity for files content, and integrity for filename.<br/>
<br/>
Additionally, with GPFS library, we are able to add security mechanism for filename confidentiality, filename integrity, file-path integrity and\
binding of files to a volume, on top of existing filesystem protection software (i.e. SGX-Protected Filesystem).<br/>
<br/>
To summarise, the Graphene Filesystem Shield extends Graphene(a system which allows existing applications to run inside SGX), with transparent protection of file I/O.<br/>
More specifically, it transparently intercepts all file I/O calls and, if the implied filename is below some pre-defined mount-points, cryptographically protects<br/>
the corresponding operations while interacting with the untrusted filesystem

For more details refer to [design document](docs/design.md).

**List of directories and components added:**
1.  [docs](docs) folder has design document. **Note: Code is NOT fully upto the design document, CHANGELOG has pending features,
and you can also refer to tag->"TODO(For Implementation)" specified in design doc for additional features yet-to-be-implemented.<br/>**
With GPFS library,  the features that have been implemented are: filename confidentiality, filename integrity, file-path integrity and binding of files to a volume,<br/>
on top of existing filesystem protection software (i.e. SGX-Protected Filesystem).<br/>
2.  [ld_preload_lib](ld_preload_lib): Has sources to intercept and overload file-system apis, and route it to SGX ProtectedFS library or to C filesystem api. Also has sources to augment cryptographic mechanisms
to add additional features as described in the design doc under docs directory.<br/>
3.  [pfs_sdk](pfs_sdk): Has a patch file that gets applied on SGX SDK's protected-fs library, to make it work within graphene, without sgx-sdk dependencies.<br/>
4.  [pfs_proxy](pfs_proxy): Has changes, to hook calls from SGX SDK-protectefs library sources, to non-sgx-sdk apis.<br/>
5.  [apps/protfs_app](apps/protfs_app): Has sources for sample graphene application, that sets the following in the<br/>
application's manifest(specifies path to proteced directory, sets the overloaded GPFS library, sets the type of key to be used for file-protection), and uses GPFS library\
transparently as a file-system shield  

**Maximum length of filenames allowed for protected files:**
Given that protected files' names are encrypted and then base64 encoded,
we have a maximum limit of 180 bytes for the length of filename of a protected file.
The [design document](docs/design.md), discusses about base64 encoding of filenames for protected files.

**Setting parameters in Graphene application's manifest:**<br/>
*Note: Refer to [README](apps/protfs/README.md) under [apps/protfs_app](apps/protfs_app) for details on how to set various parameters in application's manifest*
* Briefly, application's manifest has fields to set the overloaded library(libfileops_interceptor.so),
 directory-path where protected-files are mounted, and type of key(SGX sealing key or custom-key) is
 used to protect the files.<br/>
*Note: High-level steps for how to generate sealed_custom_key file and process it is mentioned below.*<br/>
*Note: Although [design document](docs/design.md) specifies volume-id setting in manifest, this is currently not supported yet.*<br/>

**Build steps:**
1.  Installing dependencies(under ./deps) for the build.<br/>
./build_deps.sh<br/>
Note: Above script->build_deps.sh will prompt user to install a version of Graphene,<br/>
under ./deps. Installation of graphene can be skipped by the user, if user already has Graphene<br/>
installed in a different directory path.<br/>

2.  Building the Graphene-ProtectFS library:<br/>
If user has Graphene installed in a different directory path(default path is ./deps/graphene):<br/>
i. Add a file->custom_makefile_variables, with path set to your graphene repo.<br/>
ii. Add rule below in file->custom_makefile_variables, with the directory-path.<br/>
iii. DEPS_GRAPHENE=/path_to_graphene_repo_directory_path/<br/>
and then run the script below:<br/>
./build_library.sh<br/>
Above script will copy the library(libfileops_interceptor.so)<br/>
into the Runtime directory of graphene.<br/>

3. Building sample application at apps/protfs_app:<br/>
cd apps/protfs_app<br/>
User needs to update protfs_application's manifest file with the path of Graphene and other configuration parameters.<br/>
For configuration setup, application build steps, and for details on how to set various parameters in application's manifest,<br/>
refer to [README](apps/protfs_app/README.md) under [apps/protfs_app](apps/protfs_app) <br/>

**Kernel Driver Dependencies:**
1.  Need to make sure that both SGX driver and graphene SGX driver are loaded to run graphene.<br/>
2.  [SGX Driver installation](https://github.com/intel/linux-sgx-driver) steps.<br/>
3. [Graphene SGX Driver installation](https://github.com/oscarlab/graphene/wiki/SGX-Quick-Start) steps<br/>
4. When you do lsmod | grep sgx, you would have to see the following drivers loaded:<br/>
graphene_sgx <br/>
isgx <br/>


**Steps for how to generate sealed_custom_key file:**<br/>
**Pre-requistes generate sealed_custom_key file:**<br/>
Custom key can be generated on a SGX system(Factory system A) within trusted premises(like a factory-like enviornment).<br/>
Custom key needs to sent via SGX remote attestation to the target SGX system(Target system B).<br/>
Note: These are high-level steps:<br/>
1.  SGX enclave(Enclave A) running on system A needs to generate random custom key and
send custom key to SGX enclave(Enclave B) on system B, through remote attestation.
2.  Once Enclave B(running on Target system B) receives the custom key via SGX remote attestation, it needs to 
invoke SGX sealing api, to seal the custom-key and output the sealed blob to file-system on Target system B.

**Steps for how to process existing sealed_custom_key file:**<br/>
**Pre-requisite: sealed-custom key, is generated and exists in filesystem as explained above.:**<br/>
1.  If PFS_USE_CUSTOM_KEY is set to 'yes' in application's manifest, this library(fops_interceptor.so), will expect a sealed_custom_key, in the current working directory\
of the application.<br/>
2.  If present, it will unseal the blob, and save the custom-key in graphene application's memory(application runs as SGX enclave)
3.  [Design document](docs/design.md) descibes how custom file-content protection key and other keys are derived from this custom-key.
3.  So for any C filesystem api calls that application invokes like fopen/fread/fwrite and so on, custom file-content protection key(derived 
from custom-key) will be used to protect the contents of the files.

**List of Filesystem apis handled (and the ones not handled) by library:**<br/>
**Note: For non-protected files, ALL C filesystem apis are supported.**<br/>
The list below for what is supported/not-supported, only applies <br/>
to protected files.

**List of C filesystem apis(returns or uses FILE *) supported by library:**<br/>
**SUPPORTED: For the apis below, library will intercept and route it to SGX-ProtectedFS library api:**
* fopen
* fflush
* fclose
* fread
* fwrite
* fgetc
* getc
* fgets
* fputc
* putc
* fputs
* ungetc
* ftell
* ftello
* fseek
* fseeko
* rewind
* clearerr
* ferror
* feof
* remove

**C filesystem apis(file-descriptor based apis) NOT supported by library:**
Note: Un-supported apis can still be used for files that do NOT need protection. For any calls to un-supported apis,<br/>
if the path matches with the protected_directory specified in the manifest, then GPFS library, will NOT allow those calls, <br/>
and will return an error.<br/>*

**Apis that take file-descriptor are NOT supported. APIs that create new file-descriptor like <br/>
open/openat/creat are NOT supported. Library will intercept and return error:**<br/>
* open
* openat
* creat(and their 64-bit versions).

*Since open/openat/creat are NOT supported for protected-files, any api that passes fd(file-descriptor) is NOT intercepted by the library.<br/>
Since those system calls(using file-descriptor) will be for non-protected files, it will be  directly handled  by underlying C library<br/>*

****For the un-supported (returns or uses FILE *) apis below, library will intercept and return error gracefully.:****
* freopen
* truncate
* setbuf
* setbuffer
* setlinebuf
* setvbuf
* vfscanf
* vfprintf
* fgetpos
* fsetpos
* fileno

**File-rename apis NOT supported, intercepted by library, and returns error:**
* rename
* renameat

**Wide-character FILE * apis, NOT supported, intercepted by library, and returns error:**
* fwide
* fgetwc
* getwc
* fgetws
* fputwc
* putwc
* fputws
* ungetwc
* vfwscanf
* vfwprintf

**Not feasible to intercept/overload these apis below. handled directly by C library:**
* fscanf
* fprintf
* fwscanf
* fwprintf

**List of 64-bit Filesystem apis handled (and the ones not handled) by library:**<br/>
Note: For 32-bit systems, C lib provides 64 bit versions of certain apis, mainly related<br/>
to file-open/seek/tell to support LFS(Large-File-system) on 32-bit systems.<br/>
The program should enable this conditional->_FILE_OFFSET_BITS == 64, to use 64-bit apis(and types)<br/>
on 32-bit systems. On 64-bit systems, no such conditional is needed , by default apis(and types)<br/>
are 64-bit compliant. For example, calling fseek on 64 bit-system is equivalent to calling fseek64 api.**<br/>
****SUPPORTED: List of 64-bit C filesystem apis(returns or uses FILE *) supported by library:****
* fopen64
* ftello64
* fseeko64

**64-bit C filesystem apis(file-descriptor based apis) NOT supported by library. Library will intercept and return error::**
* open64
* openat64
* creat64

****For the 64-bit un-supported (returns or uses FILE *) apis below, library will intercept and return error gracefully.:****
* freopen64
* fgetpos64
* fsetpos64


**List of directory-system handled (and the ones not handled) by library:**
**Note: For non-protected files, ALL C directory-system apis are supported.**<br/>
The list below for what is supported/not-supported, only applies <br/>
to directory-paths(where protected files reside), as set<br/>
in application's manifest.<br/>

**SUPPORTED: List of directory-system apis supported by library:**
* opendir
* closedir
* readdir
* readdir64
* rewindir
* seekdir
* telldir

**List of directory-system apis NOT-supported, intercepted by library, and returns error:**
* readdir_r
* readdir64_r
* dirfd
* scandir
* scandir64
* scandirat
* scandirat64
* nftw
* nftw64

**NO interception/handling for apis below. Since open/openat/creat are NOT supported for directory-paths<br/>
where protected-files reside** <br/>
System calls(using file-descriptor) will be for directory-paths to NON-protected files, and it will
be  directly handled by underlying C library.:<br/>
* fdopendir
* getdirentries
* getdirentries64

**NO interception/handling for apis below. Not feasible to
intercept and handle these apis.:**<br/>
* alphasort
* alphasort64
* versionsort
* versionsort64
