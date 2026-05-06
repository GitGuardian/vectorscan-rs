use crate::error::{AsResult, Error};
use bitflags::bitflags;
use foreign_types::{foreign_type, ForeignType};
use std::ffi::c_ulonglong;
use std::{ffi::CString, mem::MaybeUninit, ptr};
use vectorscan_rs_sys as hs;

foreign_type! {
    #[derive(Debug)]
    unsafe type CompileError: Send + Sync {
        type CType = hs::hs_compile_error_t;
        fn drop = compile_error_drop;
    }

    #[derive(Debug)]
    pub unsafe type Database: Send + Sync {
        type CType = hs::hs_database_t;
        fn drop = database_drop;
    }

    #[derive(Debug)]
    pub unsafe type Scratch: Send + Sync {
        type CType = hs::hs_scratch_t;
        fn drop = scratch_drop;
    }
}

unsafe fn database_drop(v: *mut hs::hs_database_t) {
    let res = hs::hs_free_database(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_database failed: {res}");
    }
}

unsafe fn scratch_drop(v: *mut hs::hs_scratch_t) {
    let res = hs::hs_free_scratch(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_scratch failed: {res}");
    }
}

unsafe fn compile_error_drop(v: *mut hs::hs_compile_error_t) {
    let res = hs::hs_free_compile_error(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_compile_error failed: {res}");
    }
}

bitflags! {
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Flag: u32 {
        const CASELESS = hs::HS_FLAG_CASELESS;
        const DOTALL = hs::HS_FLAG_DOTALL;
        const MULTILINE = hs::HS_FLAG_MULTILINE;
        const SINGLEMATCH = hs::HS_FLAG_SINGLEMATCH;
        const ALLOWEMPTY = hs::HS_FLAG_ALLOWEMPTY;
        const UTF8 = hs::HS_FLAG_UTF8;
        const UCP = hs::HS_FLAG_UCP;
        const PREFILTER = hs::HS_FLAG_PREFILTER;
        const SOM_LEFTMOST = hs::HS_FLAG_SOM_LEFTMOST;
        const COMBINATION = hs::HS_FLAG_COMBINATION;
        const QUIET = hs::HS_FLAG_QUIET;
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pattern {
    expression: Vec<u8>,
    flags: Flag,
    id: Option<u32>,
}

impl Pattern {
    pub fn new(expression: Vec<u8>, flags: Flag, id: Option<u32>) -> Self {
        Self {
            expression,
            flags,
            id,
        }
    }
}

impl Database {
    pub fn new(patterns: Vec<Pattern>, mode: ScanMode) -> Result<Self, Error> {
        Self::new_with_platform(patterns, mode, None)
    }

    /// Compile patterns targeting a specific [`Platform`].
    ///
    /// Passing `None` uses Hyperscan's default behaviour (the build host's CPU
    /// features are populated via `hs_populate_platform()`), producing a
    /// database that may not deserialize on a CPU with fewer features.
    /// Passing `Some(&Platform::generic())` produces a portable database that
    /// runs on any CPU supporting Hyperscan's baseline ISA.
    pub fn new_with_platform(
        patterns: Vec<Pattern>,
        mode: ScanMode,
        platform: Option<&Platform>,
    ) -> Result<Self, Error> {
        let mut c_exprs = Vec::with_capacity(patterns.len());
        let mut c_flags = Vec::with_capacity(patterns.len());
        let mut c_ids = Vec::with_capacity(patterns.len());
        for Pattern {
            expression,
            flags,
            id,
        } in patterns
        {
            c_exprs.push(CString::new(expression)?);
            c_flags.push(flags.bits());
            c_ids.push(id.unwrap_or(0));
        }

        let platform_ptr = platform
            .map(|p| &p.inner as *const hs::hs_platform_info_t)
            .unwrap_or(ptr::null());

        let mut db = MaybeUninit::zeroed();
        let mut err = MaybeUninit::zeroed();
        unsafe {
            hs::hs_compile_ext_multi(
                c_exprs
                    .iter()
                    .map(|expr| expr.as_ptr())
                    .collect::<Vec<_>>()
                    .as_ptr(),
                c_flags.as_ptr(),
                c_ids.as_ptr(),
                ptr::null(),
                c_exprs.len() as u32,
                mode.bits(),
                platform_ptr,
                db.as_mut_ptr(),
                err.as_mut_ptr(),
            )
            .ok()
            .map_err(|_e| {
                // The details of error value `_e` are stored in `err`; convert that and ignore `_e`
                let err = CompileError::from_ptr(err.assume_init());
                Error::HyperscanCompile(err.message(), err.expression())
            })?;
            Ok(Database::from_ptr(db.assume_init()))
        }
    }

    /// Serializes the database using `hs_serialize_database`.
    pub fn serialize(&self) -> Result<SerializedDatabase, Error> {
        let mut bytes = MaybeUninit::zeroed();
        let mut length = MaybeUninit::zeroed();

        unsafe {
            hs::hs_serialize_database(self.0.as_ptr(), bytes.as_mut_ptr(), length.as_mut_ptr())
                .ok()
                .map(|()| SerializedDatabase {
                    bytes: bytes.assume_init(),
                    length: length.assume_init(),
                })
        }
    }

    /// Deserializes a database using `hs_deserialize_database`.
    pub fn deserialize(sdb: SerializedDatabase) -> Result<Self, Error> {
        let mut db_ptr = MaybeUninit::zeroed();
        unsafe {
            hs::hs_deserialize_database(sdb.bytes, sdb.length, db_ptr.as_mut_ptr())
                .ok()
                .map(|()| Database::from_ptr(db_ptr.assume_init()))
        }
    }

    /// Deserializes a database from a borrowed byte slice.
    ///
    /// `hs_deserialize_database` copies the serialized data into its own allocation,
    /// so the input buffer does not need to outlive the call. This makes the method
    /// safe to use with `include_bytes!`-embedded databases.
    pub fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut db_ptr = MaybeUninit::zeroed();
        unsafe {
            hs::hs_deserialize_database(
                bytes.as_ptr() as *const std::os::raw::c_char,
                bytes.len(),
                db_ptr.as_mut_ptr(),
            )
            .ok()
            .map(|()| Database::from_ptr(db_ptr.assume_init()))
        }
    }

    /// Gets the size of the database in bytes using `hs_database_size`.
    pub fn size(&self) -> Result<usize, Error> {
        let mut database_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_database_size(self.0.as_ptr(), database_size.as_mut_ptr())
                .ok()
                .map(|()| database_size.assume_init())
        }
    }

    /// Gets the required size in bytes for a stream for the database using `hs_stream_size`.
    pub fn stream_size(&self) -> Result<usize, Error> {
        let mut stream_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_stream_size(self.0.as_ptr(), stream_size.as_mut_ptr())
                .ok()
                .map(|()| stream_size.assume_init())
        }
    }
}

/// Creates a deep copy of the database via serialization followed by deserialization.
impl Clone for Database {
    fn clone(&self) -> Self {
        self.serialize().unwrap().deserialize().unwrap()
    }
}

#[derive(Debug)]
pub struct SerializedDatabase {
    bytes: *mut std::os::raw::c_char,
    length: usize,
}

impl SerializedDatabase {
    #[inline]
    pub fn deserialize(self) -> Result<Database, Error> {
        Database::deserialize(self)
    }

    /// Returns the serialized database as a borrowed byte slice.
    ///
    /// The slice is tied to `self`'s lifetime — the backing C allocation is freed
    /// when `SerializedDatabase` is dropped.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `bytes` is a pointer returned by `hs_serialize_database` and valid
        // for `length` bytes until `Drop` frees it. The returned slice borrows `self`,
        // preventing use-after-free.
        unsafe { std::slice::from_raw_parts(self.bytes as *const u8, self.length) }
    }

    /// Gets the size in bytes required to deserialize this database using
    /// `hs_serialized_database_size`.
    pub fn deserialized_size(&self) -> Result<usize, Error> {
        let mut deserialized_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_serialized_database_size(self.bytes, self.length, deserialized_size.as_mut_ptr())
                .ok()
                .map(|()| deserialized_size.assume_init())
        }
    }
}

impl Drop for SerializedDatabase {
    fn drop(&mut self) {
        // XXX should technically call the deallocator function set in `hs_set_misc_allocator`,
        // but we never call that here, and the defaults are malloc/free
        unsafe {
            libc::free(self.bytes as *mut libc::c_void);
        }
    }
}

impl Clone for Scratch {
    fn clone(&self) -> Self {
        let mut scratch = MaybeUninit::zeroed();
        unsafe {
            hs::hs_clone_scratch(self.0.as_ptr(), scratch.as_mut_ptr())
                .ok()
                .map(|()| Scratch::from_ptr(scratch.assume_init()))
                .unwrap()
        }
    }
}

impl Scratch {
    pub fn new(database: &Database) -> Result<Self, Error> {
        let mut scratch = MaybeUninit::zeroed();
        unsafe {
            hs::hs_alloc_scratch(database.as_ptr(), scratch.as_mut_ptr())
                .ok()
                .map(|()| Scratch::from_ptr(scratch.assume_init()))
        }
    }

    /// Gets the size of the scratch in bytes using `hs_scratch_size`.
    pub fn size(&self) -> Result<usize, Error> {
        let mut scratch_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_scratch_size(self.0.as_ptr(), scratch_size.as_mut_ptr())
                .ok()
                .map(|()| scratch_size.assume_init())
        }
    }
}

impl CompileError {
    fn message(&self) -> String {
        unsafe {
            let err = self.0.as_ptr();

            std::ffi::CStr::from_ptr((*err).message)
                .to_str()
                .unwrap()
                .into()
        }
    }
    fn expression(&self) -> i32 {
        unsafe { (*self.0.as_ptr()).expression }
    }
}

bitflags! {
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct ScanMode: u32 {
        const BLOCK = hs::HS_MODE_BLOCK;
        const VECTORED = hs::HS_MODE_VECTORED;
        const STREAM = hs::HS_MODE_STREAM;
        const SOM_SMALL = hs::HS_MODE_SOM_HORIZON_SMALL;
        const SOM_MEDIUM = hs::HS_MODE_SOM_HORIZON_MEDIUM;
        const SOM_LARGE = hs::HS_MODE_SOM_HORIZON_LARGE;
    }
}

bitflags! {
    /// Optional CPU features to advertise when compiling a database with an
    /// explicit [`Platform`]. These mirror the `HS_CPU_FEATURES_*` flags in
    /// the Hyperscan C API and are advisory: setting a feature here tells
    /// Hyperscan it may emit code paths that require it, which means the
    /// resulting database will fail to deserialize on a CPU that lacks it.
    ///
    /// For maximum portability, leave this empty (or use [`Platform::generic`]).
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct CpuFeatures: c_ulonglong {
        const AVX2 = hs::HS_CPU_FEATURES_AVX2 as c_ulonglong;
        const AVX512 = hs::HS_CPU_FEATURES_AVX512 as c_ulonglong;
        const AVX512VBMI = hs::HS_CPU_FEATURES_AVX512VBMI as c_ulonglong;
    }
}

/// Tuning hint for the host microarchitecture, mirroring `HS_TUNE_FAMILY_*`.
///
/// This guides Hyperscan's optimisation choices but does not gate
/// deserialization: a database tuned for one family will still load on a
/// different family with the same CPU feature set.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u32)]
pub enum Tune {
    #[default]
    Generic = hs::HS_TUNE_FAMILY_GENERIC,
    SandyBridge = hs::HS_TUNE_FAMILY_SNB,
    IvyBridge = hs::HS_TUNE_FAMILY_IVB,
    Haswell = hs::HS_TUNE_FAMILY_HSW,
    Silvermont = hs::HS_TUNE_FAMILY_SLM,
    Broadwell = hs::HS_TUNE_FAMILY_BDW,
    Skylake = hs::HS_TUNE_FAMILY_SKL,
    SkylakeServer = hs::HS_TUNE_FAMILY_SKX,
    Goldmont = hs::HS_TUNE_FAMILY_GLM,
    IceLake = hs::HS_TUNE_FAMILY_ICL,
    IceLakeServer = hs::HS_TUNE_FAMILY_ICX,
}

/// Target platform descriptor passed to the database compile calls.
///
/// Hyperscan databases compiled with the default (`null`) platform inherit the
/// build host's CPU features via `hs_populate_platform`, so a database built on
/// an AVX2-capable host will refuse to deserialize on a CPU without AVX2. To
/// produce a portable database, pass [`Platform::generic`] (no CPU features
/// advertised); to faithfully reproduce default behaviour, pass
/// [`Platform::native`].
///
/// Construct with a builder pattern: `Platform::generic().with_tune(Tune::Skylake)`.
#[derive(Clone, Copy, Debug)]
pub struct Platform {
    inner: hs::hs_platform_info_t,
}

impl Platform {
    /// A baseline platform: generic tuning, no optional CPU features
    /// advertised. The resulting database is portable to any CPU supporting
    /// Hyperscan's mandatory ISA baseline (SSE4.2 on x86_64, NEON on aarch64).
    pub fn generic() -> Self {
        Self {
            inner: hs::hs_platform_info_t {
                tune: hs::HS_TUNE_FAMILY_GENERIC,
                cpu_features: 0,
                reserved1: 0,
                reserved2: 0,
            },
        }
    }

    /// Populate from the running host's CPU features via
    /// `hs_populate_platform`. Equivalent to passing `null` to the underlying
    /// compile call; useful when you want an explicit record of what was
    /// targeted, or as a starting point for further customisation.
    pub fn native() -> Result<Self, Error> {
        let mut info = MaybeUninit::<hs::hs_platform_info_t>::zeroed();
        unsafe {
            hs::hs_populate_platform(info.as_mut_ptr())
                .ok()
                .map(|()| Self {
                    inner: info.assume_init(),
                })
        }
    }

    pub fn with_tune(mut self, tune: Tune) -> Self {
        self.inner.tune = tune as u32;
        self
    }

    pub fn with_cpu_features(mut self, features: CpuFeatures) -> Self {
        self.inner.cpu_features = features.bits();
        self
    }

    pub fn cpu_features(&self) -> CpuFeatures {
        CpuFeatures::from_bits_truncate(self.inner.cpu_features)
    }

    /// Returns the raw `HS_TUNE_FAMILY_*` constant; use [`Self::cpu_features`]
    /// for the typed feature set.
    pub fn tune_raw(&self) -> u32 {
        self.inner.tune
    }
}

impl Default for Platform {
    fn default() -> Self {
        Self::generic()
    }
}
