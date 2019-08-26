Design of the Graphene Protected Filesystem Shield
===============================================================================
* **Author:** *Sudha Krishnakumar <sudha.krishnakumar@intel.com>*, *Michael Steiner, <michael.steiner@intel.com>*
* **Version:** *0.4*

# Context and Problem Statement #

The *Graphene Filesystem Shield* is extends *[Graphene](https://grapheneproject.io/)*, a system
which allows existing binaries to run inside SGX, with
transparent protection of file I/O. More specifically, it
transparently intercepts all _file I/O_ calls and, if the implied
filename is below some pre-specified mount-points, cryptographically
protects the corresponding operations while interacting with the
untrusted filesystem.  The (hierachy of) files below a
specific mount-points is called a _volume_. Each volume is represented
also as a sub-directory (hierachy) in the untrusted filesystem (in the
current version there is a one-to-one correspondence of files to the
trusted space in addition to a few meta-data files although that might
change in the future and no assumptions should be made on structure
and content).

## Security Properties ##

Let us first list security properties which we might desire from such
a system.  Later we will discuss their relative importance and which
can be handled where and how.

* File Content
  * *File Content Confidentiality (**FCC**)*: All file content is
    hidden from an attacker.
  * *File Content Integrity (**FCI**)*: No attacker is able to tamper
    with file content without detection.

* File Metadata
  * *Filename Integrity (**FNI**)*: No attacker is able to tamper
    with basename of a file without detection, e.g., she cannot rename
    protected files.
  * *Filename Confidentiality (**FNC**)*: The basename of files is
    hidden from attackers.
  * *File Attribute Integrity (**FAI**)*: File attributes like
    permissions, file-type (e.g., symbolic links), owners or
    modification times cannot be tampered with.
  * *File Attribute Confidentiality (**FAC**)*: File attributes like
    permissions, owners or modification times are hidden from attacker.
  * *File Existence Integrity (**FEI**)*: An attacker cannot hide a
    previously created protected file.

* Volume Metadata
  * *Path Integrity (**PI**)*: An adversary cannot tamper with the
    complete pathname inside a volume, i.e., he cannot move a protected
    file to a different sub-directory under the same mount-point.
  * *Directory Name Confidentiality (**DNC**)*:  An attacker doesn't
    learn the names of directories.
  * *Volume Binding (**VB**)*: Protected files are tied to a
    specific volume, i.e., an attacker cannot move or duplicate files
    from one volume to another one volume, whether they are mounted
    for the same graphene application instance at two different
    mount-points or two different graphene application instances at
    the same mount-point path.

* Other
  * *Rollback Protection (**RP**)*: An adversary is unable to revert the
    state to earlier version. State can refer to (parts of a) files as
    well as meta-data (e.g., existence of file).
  * *Access Patterns Hiding (**APH**)*: Prevent the adversary from inferring
    information on file content based on access patterns. Some aspects
    of are *File Existence Hiding*, *Path Hiding* or alike.


## ProtectFS ##
The SGX SDK already provides file-based encryption and integrity
protection in form of the ProtectFS functions (see [SGX Developer Guide](https://software.intel.com/sites/default/files/managed/47/19/sgx-sdk-developer-reference-for-windows-os.pdf). More specifically, it provides FCC, FCI and
FNI.  As it assumes a flat non-hierachical namespace, PI, DNC, VB are
out-of-scope.

It is targeted for greenfield applications, which usually can ensure
that filenames do not leak sensitive information. Hence the absence of
FNC is not an issue. Similarly, such applications can easily adapt to
the absence of FAI, FAC and FEI.

RP is currently not supported. However, the architecture and code is
prepared for rapid enablement once a scalable monotonic counter
solution exists.

APH is also considered out-of-scope: Susceptability of attacks
exploiting access patterns is highly application dependent and
requires more sophisticated exploitation techniques. If protection is
required, the application might have to adopt "usual" side-channel
protection techniques for file access and/or a protected file-system
based (expensive) ORAM techiques might have to be implemented.


## Implications for Graphene Filesystem Shield ##

Basing the filesystem shield on ProtectFS seems a natural approach. As
mentioned above, it already provides key security properties. However,
in the Graphene case, we have no control over assumptions made by
application, e.g., filenames could contain sensitive information,
graphene exposes a hierchical filenname space and the application
might require multiple volumes mounted to multiple mount points. Hence
FNC, DNC, PI and VB cannot be as easily dismissed.

In the following, we discuss some lightweight extensions to ProtectFS
which can provide some of these properties.

RP, as mentioned in the section on ProtectFS, will have to wait until
there is a scalable monotonic counter solution integrated into
ProtectFS, but then will naturally translate also to the shield.

To provide strong RP covering also meta-data. To achieve this, one
would require a quite different approached based on block-level
security, like dm-crypt, dm-verity and/or
[dm-x](https://github.com/anrinch/dmx) with an in-graphene filesystem
(similar to [lkl-sgx](https://github.com/lsds/sgx-lkl)). This would
also provide some form of) ABH. However, it would require a
considerable larger effort to build and is currently out-of-scope.


# Design Overview #

File I/O is intercepted (based on an `LD_PRELOAD` handler) and files
behind a mount-point are protected using ProtectFS. However,
additionally, we preprocess filenames such that the names visible to
the untrusted system is encrypted and additionally tied to volume and
path-name.

More specifically

- each volume has associate *volume meta data* containing volumne ID,
  key-type and information required for key-derivation such as
  MRSIGNER, CPUSVN, ISVSVN and KEY-ID. The volume meta data is created
  and managed by shield and stored in (hidden/special) file in root
  directory of a volume.  The metadata should be bound to the graphene
  manifest for pre-existing volumes so a party interacting with the
  graphene application can track use of volumes across application
  instances based on attestation.

- For each intercepted graphene application functions involving
  filenames in protected volumes, we encrypts file-name's path
  components before passing the call with encrypted filename to
  ProtectFS or other related functions (e.g., opendir).  The
  encryption performed based on a deterministic tweakable wide-block
  cipher with the filename padded to equal length and with (hash of)
  volumne-id and path-prefix as tweak.

- Similarly, intercepted functions where a filename is passed
  from the untrusted system, e.g., readdir, will be decrypted and
  passed in clear to the graphene application.

The encryption will ensure FNC and, potentially, DNC. Redundancy in
the filename encoding  ensures that anything violating PI and VB is
detected during decryption.

The design supports both key-management types of ProtectFS, `seal` and
`custom`.  See below for more details on the key-management. In
particular, note though that custom keys passed to the shield are
_not_ passed to protectfs but used to derive a separate custom key
which is passed to ProtectFS.


# Design Details #

## Volume Metadata ##

### Data structures ###

    struct {
		protected-data: struct {
			key-type: { "custom", "seal" }
			key-derivation data: struct {
				key-id: sgx_key_id_t
				union {
					case key-type=="custom":
					case key-type=="seal": struct {
						cpusvn: SVN
						isvsvn: SVN,
						MRSIGNER
					}
				}
			}
		}
		vol-id = MAC_VMK(protected-data)
	}

`MAC` is `CMAC-AES128` [[NIST SP800-38B]](https://csrc.nist.gov/publications/detail/sp/800-38b/archive/2005-05-01).
The key `VMK` is defined below in section keys.

- **MAC Encoding in Voume-meta-data:** Encoding of payload for MAC (i.e., vol-id of
  protected-data blob) is the byte-sequence of a c-struct
  corresponding to `protected-data` from above.<br/>

### Volume Metadata File name ###
- A (hidden) file named as `.protectfs_vol_md.json` under (volume root
directory, referred as `PFS_MOUNT_POINT` in graphene manifest).<br/>
**TODO (For implementation)**: Current implementation outputs a binary file
`.protectfs_vol_md.bin`, will be changed, once json format is supported.

### Volume Metadata File encoding ###
- Will be encoded in json, so that it is human readable, and allows
  for easy extraction of the volume-id (which is required
  to set `vol-id` field in manifest!)<br/>
**TODO (For implementation)**: Currently implementation stores this file
in binary format. To be changed to json in future.


### Volume binding in Graphene Manifest ###
The Graphene manifest will be extended with following
(per-volume/mountpoint) values:
- *`PFS_MOUNT_POINT` (referred as `mount-point` in this doc)* :
  the mount point in the graphene internal namespace
  below the volume is mounted (already existing in current implementation)
- *`PFS_VOL_ID` (referred as `vol-id` in this doc)*: the id of a pre-existing
volume to mount (optional,
  mutually exclusive with `allow-reuse`)
- *`PFS_ALLOW_REUSE` (referred as `allow-reuse` in this doc)* : defines whether
  in absence of `vol-id` an existing volume under the mount point can be re-used
  or a new volume must be created (optional, mutually exclusive with `vol-id`,
  default false)

Below we will refer to them as mf.mount-point, mf.vol-id and
mf.allow-reuse for some particular manifest mf

**TODO (For implementation)**:
  In the future, if implementation supports multiple volumes, naming scheme is
  likely to change. For example, each volume's attributes can be grouped
  under a label, and set in the manifest (somewhat matching the mount point
  mappings in the standard graphene manifest, like `PFS.mount.<label>`,
  `PFS.vol-id.<label>` and `PFS.allow-reuse.<label>`)



### Volume Meta data Processing ###

    - on start of graphene (with manifest mf) or, (less ideally due to
      late errors) before first FILE access
      - try to read volume meta data file content into variable md
	  - if file exists
        - if (!defined(mf.vol-id) AND (!defined(mf.allow-reuse) OR mf.allow-reuse=false)
	          error NO_REUSE_ALLOWED
        - if (defined(mf.vol-id))
          - verify that md.vol-id = mf.vol-id
        - compute keys VCK, VNK, VMK (see definition below) & keep
		  them in memory during the live time of the volume
    	- verify MAC_VMK(md.protected-data) = mf.vol-id
      - else // volume meta data file does not exist
        - if defined(mf.vol-id)
	       error VOLUME_NOT_FOUND
        - randomly select md.key-id for in-memory meta-data structure and add
          key-type to it
        - retrieve current cpusvn, isvn, MRSIGNER from sgx report and fill
          corresponding fields in-memory meta-data structure md.
        - compute VCK, VNK & VMK (see definition below) & keep
		  them in memory during the live time of the volume
    	- compute md.vol-id = MAC_VMK(md.protected-data)
    	- write md to volume meta-data file
      - abort if any of above fails

## Keys ##

* *Volumne-wide content encryption key (**VCK**)*: key passed to protectfs
	iff key-type=="custom".
* *Volumne-wide name encryption key (**VNK**)*: EME2-AES128 [[IEEE P1619.2]](https://doi.org/10.1109/IEEESTD.2011.5729263)
  key to encrypt file and directory names.

  **TODO (For implementation)**: Current implementation uses
  AES128-XTS instead, see below [discussion](#discussion) below for
  implications of using XTS instead of EME2.
* *Volumne-wide meta-data integrity key (**VMK**)*: CMAC-AES128 key to
	compute message integrity over volume meta-data.

ProtectFS and the network shield allow for two ways keys are
provided: Either based on SGX seal key or on an user-provided custom
key. Depending the type, above keys are derived differently as follows

### Case: SGX Seal-key ###
* VCK: null, protectfs internally uses EGETKEY Seal key for that

* VNK: this is the concantenation of `KAD | KECB | KAES` where the
  components are computed via invocation of EGETKEY/sgx_get_key as in
[generate_random_meta_data_key](https://github.com/01org/linux-sgx/blob/master/sdk/protected_fs/sgx_tprotected_fs/file_crypto.cpp),
  with

  - `key_request.key_id = key-id1` for `KAD`, `key-id2` for `KECB` and `key-id3` for `KAES`
  - `key_request.key_policy = SGX_KEYPOLICY_MRSIGNER`
  - `key_request.cpu_svn = md.protected_data.cpusvn`
  - `key_request.isv_svn = md.protected_data.isv_svn`
  - `key_request.attribute_mask = {TSEAL_DEFAULT_FLAGMASK, 0x0}`,
  - `key_request.misc_mask = TSEAL_DEFAULT_MISCMASK`.

  **TODO (For implementation)**: Currently with AES-XTS, this is just
  the first 32 bytes of above.

* VMK: a single EGETKEY invocation as above but with `key_request.key_id`=`key-id4`.

`key-id1`, `key-id2`, `key-id3` and `key-id4` are computed from `mf.key-id` as
follows (with & and | binary AND and OR):

- `key-id1 = mf.key-id & ~0x3) | 1`
- `key-id2 = mf.key-id & ~0x3) | 2`
- `key-id3 = mf.key-id & ~0x3) | 3`
- `key-id4 = mf.key-id & ~0x3) | 4`


### Case: User-provided custom key ###

* VCK: cmac-in-counter KDF ([SP800-108](https://csrc.nist.gov/publications/detail/sp/800-108/final)) as in
  [generate_secure_blob](https://github.com/01org/linux-sgx/blob/master/sdk/protected_fs/sgx_tprotected_fs/file_crypto.cpp),
  with
	- user-provided custom-key as key,
    - `label "SGX-PROTECTED-FS+-VOLUME-CONTENT-KEY",`
	- `buf.nonce32 = mf.key-id` and
    - `buf.output_len = 0x80` (128 bit).

* VNK: same as above but with
  - `label "SGX-PROTECTED-FS+-VOLUMNE-NAME-KEY"`
  - `buf.nonce32 = mf.key-id` and
  - `buf.output_len = 0x180` (384 bit).

  As we need 48 bytes, we have to performa three invocation of
  (sgx_rijndael128_cmac_msg)[https://download.01.org/intel-sgx/linux-2.5/docs/Intel_SGX_Developer_Reference_Linux_2.5_Open_Source.pdf], with `buf.index = 2` (i.e., increment by 1)
  before the second invocation and `buf.index = 3` before the third.
  The result is the concatenation of both outputs.

* VMK: same as above but with
  - `label "SGX-PROTECTED-FS+-VOLUMNE-METADATA-KEY"`,
  - `buf.nonce32 = mf.key-id` and
  - `buf.output_len = 0x80` (128 bit).


## Encryption/Decryption Mechanism ##

Assuming our interceptor decided that the file requires protection,
i.e., it is below the mount-point of a volume, encryption and
decryption will handled as follows

### Encryption ###

	- normalize filename
	- decompose filename in <pre-mt,vol-path,base-name>
      with
	  - pre-mt: path up to (and including) mount-point, i.e., it
	    should correspond to PFS_MOUNT_POINT.
	  - vol-path: directory-path inside volume excluding last path
        component, can be empty string
	  - base-name: last path component, either file or directory if
        path is directory
    - check basename is valid \0-terminated UTF-8 string
    - zero-pad to 192 bytes
    - compute tweak as concatenation (volID | vol-path)
    - encrypt with above tweak, VNK and above computed padded filename
	  (see definition of VNK for used block cipher)
    - Base64-encoded to 256 bytes

**TODO (For Implementation)**: Current implementation only checks for
valid ascii string. Will be changed to UTF-8 string check in future.


### Decryption ###

	- normalize filename
	- decompose in <pre-mt,vol-path,enc-base-name>
    - Base64-decode enc-base-name to 192 bytes
    - compute tweak as concatenation (volID | vol-path)
    - decrypt with above tweak, VNK and enc-base-name
	  (see definition of VNK for used block cipher)
    - verify that returned basename is (a) a valid \0-terminated UTF-8
      string and (b) is zero-padded to 192 bytes
    - abort if anything above fails


**TODO (For Implementation)**: Current implementation only checks
for valid ascii string. Will be changed to UTF-8 string check in future.


## Shield integration ##
**TODO (For implementation)**: Given that protected files' names are encrypted and
then base64 encoded,we have a maximum limit of 180 bytes for the length of
filename of a protected file. design doc has specified 192 bytes, to investigate
 if we can support upto 192 bytes in implementation*

### Intercepting filesystem apis: ###

**As per current implementation, sequence of steps, and applying additional (FNC, FNI, PI, VB) security
mechanisms during filename encryption:**<br/>
* Application opens a file(filename in clear) with path to protected
*   directory path(PFS_MOUNT_POINT) set in graphene manifest.
* Graphene-filesystem-shield library intercepts the call to C fopen api,
*   and does filename encryption:
    * Does zero-padding of filename to 180 bytes.
    * Retrieves the directory-path (i.e. location) of the file to be opened.
    * Computes tweak->Hash of (directory-path || Volume-ID).
    * Enforces that filename is a valid ascii string.
        * **TODO (For Implementation)** utf-8 check.
    * Uses tweakable block cipher mode to do filename encryption.
    * Base64-encoded to 246 bytes
* Passes the encrypted filename to SGX-ProtectFS:
* SGX-ProtectFS does file’s content encryption.
* SGX-ProtectFS, uses filesystem apis to access/update the file, using the
*  encrypted filename in the Host system.

**As per current implementation, sequence of steps for filename decryption:**<br/>
* Application calls opendir, followed by readdir api, to read filenames.
* Graphene-filesystem-shield library intercepts the call to readdir api,
* and does filename decryption:
    * Base64-decode of encoded-base-name to 180 bytes
    * Retrieves the directory-path (i.e. location) of the file to be opened.
    * Computes tweak->Hash of (directory-path || Volume-ID).
    * Uses tweakable block cipher mode to do filename decryption.
    * Encoding checks, after decryption:
    * Checks that filename is a valid ascii string.
        *   **TODO (For Implementation)** utf-8 check.
        *   Has zero-padding of filename to fixed max length of 180 bytes.<br/>
** Note: If there are any security attacks related to, FNI (like attacker
modifies the encrypted filename), Path-Integrity (attacker moves the file to a
different location), and/or Volume-Binding (attacker moves the file to a
different volume), then encoding checks above will fail.*
* If above steps are successful, we return the decrypted name to application. 

**For complete list of intercepted functions(filesystem and
  directory-system) apis handled(and the ones not handled)
  please refer to section in README**
  
Any untrusted system provide name (e.g., from readdir) must be
decrypted) where as app-provided names (e.g., fopen, opendir) must be
encrypted before passed to protectfs.

**Q:** Name translation might also have to be done for functions like
fstat et al?  The actual interception, though, is following a general
structure:
- any input filename has to be encrypted before passing on
- any output filename has to be decrypted before passing on
- for callback function parameter with filenames as parameter, like
  the filter() and compare() for scandir, one would have to
  dynamically wrap the provided function with a new function which
  encrypts/decrypts filenames depending on whether they are input or
  output params [**Q:** conceptually such function wrapping is easy with
  anonymous lambda's/closures but how to do it best in C? For scandir
  the scope is only the function invocation, so it could be a
  stackbased function, though, ...]


# Questions #

***TODO**: Resolve below questions (and any inline **Q:**-marked questions ...*


- pathname normalization:
  - _must_ resolve relative paths, ../ and ./ and alike! Do we do
    right now?
  - what about _symbolic links_?
	aspects
	- link direction
       1. outside link point in: results in unprotected files inside volume
       2. inside link point out
	   3. inside point to other inside (in same or different volume)?
    - link location
	   1. symlink outside, hidden from inside: "normal"
          file-replacement, should be handled by PI & VB, i.e., just
          DoS?
       2. symlink outside and exposed to inside:

     - without FAI, adversary can switch forth and back without us
       directly noticing, but if points to (existing) inside file,
       should fail due to PI/FNI. if during creation,

	what about names which are returned from opendir and alike? App
    should have only read-only non-shield protected files or bets are
    essentially off (i.e., application must deal with it) and so (1)
    is non-issue as file wouldn't match graphene manifest. (2) is
    handled by PI and FNI unless symlink is exposed to inside


# Security Analysis #

In the following, we assume FCC, FCI and FNI are provided by ProtectFS
-- see corresponding security analysis in the ProtectFS documentation --
and we will just argue that above design also provides FNC, DNC, PI
and VB.

* FNC & DNC
  - FNC & DNC is ensured by the way we encrypt names. As encryption is
    the same for both directories and file, the following reasoning
    applies to both FNC and DNC.

  - for file-based encryption system, for practicality reasons we
    require a deterministic way to map names to their encrypted and
    changes to file are always linkable. This puts limits to achievable
    semantic security. The best we can hope is that

	1. a (encrypted) filename cannot be distinguished from a random
      filename in the same directory unless the adversary knows the
      filename already completely and
    2. for files in different directories, the adversary cannot tell
      whether they have the same name or not.

	This is exactly what the design achieves. Assuming EME2-AES128 is
    a secure tweakable wide-block cipher mode, then (2) is achieved
    due to randomization guarantees of tweaks and (1) is ensured by
    padding names to a uniform length and due to the properties of the
    cipher.

	Note also that our encoding and corresponding verification on
    decryption guarantees integrity even though EME2-AES128 does per se
    not provide any integrity. Assuming that EME2 is an independent secure
    pseudo-random-permutation for each tweak -- as stipulated in the
    security definition used in the [security analysis of
    EM*](https://eprint.iacr.org/2004/125) which provides foundation
    of EME2 -- our construction will provide [`INT-CTXT`](https://doi.org/10.1007/s00145-008-9026-x): 
    Any tampering of received ciphertext (or guessing thereof)  will result in
    unpredictable random cleartext for random permutations and
    probability of a random name of proper length decrypting correctly
    when used with zero-padding and UTF-8 check is $`< 2^{-159}`$. 
    Alternatively, checking for
    zero-padding and ASCII-7 names would improve security even to $`<
    2^{-195}`$, although by removing support for UTF-8 filenames. (If
    we would verify only zero-padding but not UTF-8, probability would
    be only $`<2^{-11}`$.)  The same propabilities also holds if we
    pass wrong key or tweak for an existing encrypted name.

	Note that our primary concern is that an existing encrypted name
    (with associated encrypted file) cannot be successfully decrypted
    in a wrong context (path, key).  An existential forgery of a
    properly decrypting new name could be used to fool an application
    using opendir/readdir of the existance of a random (unpredictable)
    filename but the adversary could never provide an actual file for
    that name.  Insofar, assuming that the underlying cipher is secure
    against adaptive adversaries, we wouldn't have to worry much
    adaptively attacking the decoding checks, e.g., via timing
    side-channels.

* PI
  - The randomization by the tweak and the integrity of the encryption
    (see above) guarantee that an encrypted name can be (re-)used only
    with the expected path. FNI (on the encrypted filename) ensured by
    ProtectFS makes sure that the binding of path to file is fixed.


* VB.
  - VB is guaranteed as (a) volume ids are unique (enclave guarantees
    randomness due to random choice of keyid), (b) all keys used are
    unique to a particular volume and (c) we verify integrity on both
    files and meta-data, i.e., any operation where key and file are
    not part of same volume will fail.




# Discussion #

- The only currently tweakable deterministic cipher in NIST standards
  is XTS-AES128 [NIST SP 800-38E](https://csrc.nist.gov/publications/detail/sp/800-38e/final)
  and it is used in the domain which triggered wide-block ciphers:
  storage encryption. Alas, XTS is _not_ a wide-block cipher and it's
  use would leak any common 16-byte blocks of filenames in the same
  directory and the filename length. The only standardized wide-block
  ciphers are EME2-AES and XCB-AES in [IEEE P1619.2](https://doi.org/10.1109/IEEESTD.2011.5729263).
  The latter, though, has a number of [security concerns](https://eprint.iacr.org/2013/823)
  making the former the prefered choice. A third secure
  wide-block-cipher choice would be
  [CMC](https://doi.org/10.1007/978-3-540-45146-4_28). It was
  designed by the same authors who developped the foundation of EME2,
  i.e., [EME](https://doi.org/10.1007/978-3-540-24660-2_23) and
  [EME*](https://doi.org/10.1007/978-3-540-30556-9_25) but due to the
  lack of parallelization -- irrelevant for us but important for
  hardware implementations -- was not standardized even though the
  construction (and security proof) is a bit simpler.

- Practicality considerations aside, the only potential advantage a
  non-deterministic cipher could provide is that we could also hide
  when a file with a given filename is created, deleted and then
  another file with the same filename is created.  However, this does
  not seem worth the trade-off given the vastly increased
  implementation complexity of a randomized cipher and other more
  relatively serious leakage related to access patterns on file block
  access and alike (APH).

- integrity via AAD would be natural but would require changes to protectfs

- MAC over volume data is to ensure that key-ids are random and not
  reused, as done, e.g., by protectfs. That way, we ensure that we do
  not have an encryption/decryption oracle for target key in
  wrong/different context.

- PI and VB could be attained somewhat more intuitive by using AAD.
  However, this would require changes (and hence a fork) in ProtectFS
  itself whereas the current design can treat it as a blackbox.

- filename constraints: zero-padded UTF-8 \ { /, \0 } least
  constraining and enough security, input-validation consideration
  could ask for further constraints but (a) as far as our code is
  concerned this should be enough --- _*CHECK* are we currently
  doing/considering input validation? in fs shield? in network shield?
  in graphene?_ ---, (b) to a large extent we have
  to rely anyway that code further down the pipeline is robust (and
  hence does proper checking) and (c) it is hard (impossible?) to
  define a subset which is guaranteed to be robust

- we could add support also for MRENCLAVE for custom-keys if required,
  though seems currently to be not so useful, at least as long as
  graphene manifest is embedded in MRENCLAVE ..

- volume meta-data is not directly externally verifiable. However, we
  _do_ know when using an existing volume that (a) which one is used (due
  to inclusion in graphene manifest visible in attestation, unless
  explicitly opt-ed out with 'allow-reuse==true') and (b) tampered
  data such as MR* and alike make shield fail. One could also imagine
  adding a quote but it wouldn't really add anything. Note also that
  given that we don't currently have FEI and FAI we could anyway not
  verify that files are part of volume or alike. For that we would
  need a block-level protected volume.

- CMAC for MAC seems a pragmatic solution as used elsewhere also in
  ProtectFS, HMAC would provide more security but is slower, GMAC is
  asymptotically (much) faster in HW but needs iv and we don't care
  about asymptotics, MAC payload is fairly slow. (umac/vmac/poly1305
  would be other reasonable options but they are not in Suite B)
