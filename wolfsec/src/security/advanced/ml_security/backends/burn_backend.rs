use burn::backend::{NdArray, Autodiff};
use burn::tensor::Tensor;

// Define the backend types. 
// We default to NdArray (CPU) for broad compatibility, but this can be switched to Wgpu.
pub type Backend = NdArray;
pub type AutodiffBackend = Autodiff<Backend>;

pub struct BurnBackend;

impl BurnBackend {
    pub fn new() -> Self {
        Self
    }

    /// Helper to create a tensor from a float slice
    pub fn from_floats(data: &[f32], device: &<Backend as burn::tensor::backend::Backend>::Device) -> Tensor<Backend, 1> {
        Tensor::from_floats(data, device)
    }
}

// Future expansion: Add specific Burn model loading logic here