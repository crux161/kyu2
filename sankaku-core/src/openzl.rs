use anyhow::{Context, Result, bail};
use std::ptr::NonNull;

use sankaku_openzl_sys::{
    OPENZL_ALLOCATION_FAILED, OPENZL_INVALID_INPUT, OPENZL_OK, OPENZL_OUTPUT_TOO_SMALL,
    OpenZlContextOpaque, OpenZlSaoInputBuffer, OpenZlSaoOutputBuffer, OpenZlSerializedGraph,
    openzl_context_create, openzl_context_destroy, openzl_context_update_graph, openzl_decode_sao,
    openzl_encode_sao,
};

fn map_error(code: i32) -> anyhow::Error {
    match code {
        OPENZL_INVALID_INPUT => anyhow::anyhow!("OpenZL rejected input pointers"),
        OPENZL_OUTPUT_TOO_SMALL => anyhow::anyhow!("OpenZL output buffer too small"),
        OPENZL_ALLOCATION_FAILED => anyhow::anyhow!("OpenZL allocation failed"),
        _ => anyhow::anyhow!("OpenZL returned error code {code}"),
    }
}

fn to_graph(serialized_graph: &[u8]) -> OpenZlSerializedGraph {
    OpenZlSerializedGraph {
        data: serialized_graph.as_ptr(),
        len: serialized_graph.len(),
    }
}

fn to_input(payload: &[u8]) -> OpenZlSaoInputBuffer {
    OpenZlSaoInputBuffer {
        data: payload.as_ptr(),
        len: payload.len(),
    }
}

fn to_output(buffer: &mut [u8]) -> OpenZlSaoOutputBuffer {
    OpenZlSaoOutputBuffer {
        data: buffer.as_mut_ptr(),
        len: buffer.len(),
    }
}

/// Stateful OpenZL context that can update compression graphs at runtime.
pub struct OpenZlContext {
    raw: NonNull<OpenZlContextOpaque>,
    serialized_graph: Vec<u8>,
}

impl OpenZlContext {
    pub fn new(serialized_graph: &[u8]) -> Result<Self> {
        let raw = unsafe { openzl_context_create(to_graph(serialized_graph)) };
        let raw = NonNull::new(raw).context("OpenZL returned a null context")?;
        Ok(Self {
            raw,
            serialized_graph: serialized_graph.to_vec(),
        })
    }

    pub fn update_graph(&mut self, serialized_graph: &[u8]) -> Result<()> {
        let rc =
            unsafe { openzl_context_update_graph(self.raw.as_ptr(), to_graph(serialized_graph)) };
        if rc != OPENZL_OK {
            bail!(map_error(rc));
        }
        self.serialized_graph.clear();
        self.serialized_graph.extend_from_slice(serialized_graph);
        Ok(())
    }

    pub fn graph(&self) -> &[u8] {
        &self.serialized_graph
    }

    pub fn encode_sao(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.process(payload, true)
    }

    pub fn decode_sao(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.process(payload, false)
    }

    fn process(&self, payload: &[u8], encode: bool) -> Result<Vec<u8>> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }

        let mut output = vec![0u8; payload.len().saturating_mul(2).max(1)];
        loop {
            let mut written = output.len();
            let rc = unsafe {
                if encode {
                    openzl_encode_sao(
                        self.raw.as_ptr(),
                        to_input(payload),
                        to_output(&mut output),
                        &mut written,
                    )
                } else {
                    openzl_decode_sao(
                        self.raw.as_ptr(),
                        to_input(payload),
                        to_output(&mut output),
                        &mut written,
                    )
                }
            };

            if rc == OPENZL_OUTPUT_TOO_SMALL {
                output.resize(output.len().saturating_mul(2).max(payload.len() + 1), 0);
                continue;
            }
            if rc != OPENZL_OK {
                bail!(map_error(rc));
            }

            output.truncate(written);
            return Ok(output);
        }
    }
}

impl Drop for OpenZlContext {
    fn drop(&mut self) {
        unsafe { openzl_context_destroy(self.raw.as_ptr()) };
    }
}
