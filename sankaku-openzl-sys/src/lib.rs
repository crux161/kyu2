use std::ffi::c_int;

pub const OPENZL_OK: c_int = 0;
pub const OPENZL_INVALID_INPUT: c_int = -1;
pub const OPENZL_OUTPUT_TOO_SMALL: c_int = -2;
pub const OPENZL_ALLOCATION_FAILED: c_int = -3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenZlSerializedGraph {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenZlSaoInputBuffer {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenZlSaoOutputBuffer {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct OpenZlContextOpaque {
    _private: [u8; 0],
}

#[link(name = "openzl")]
unsafe extern "C" {
    pub fn openzl_context_create(
        serialized_graph: OpenZlSerializedGraph,
    ) -> *mut OpenZlContextOpaque;
    pub fn openzl_context_update_graph(
        context: *mut OpenZlContextOpaque,
        serialized_graph: OpenZlSerializedGraph,
    ) -> c_int;
    pub fn openzl_context_destroy(context: *mut OpenZlContextOpaque);

    pub fn openzl_encode_sao(
        context: *const OpenZlContextOpaque,
        input: OpenZlSaoInputBuffer,
        output: OpenZlSaoOutputBuffer,
        output_len: *mut usize,
    ) -> c_int;

    pub fn openzl_decode_sao(
        context: *const OpenZlContextOpaque,
        input: OpenZlSaoInputBuffer,
        output: OpenZlSaoOutputBuffer,
        output_len: *mut usize,
    ) -> c_int;
}
