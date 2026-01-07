pub struct ScalarQuantizer;

impl ScalarQuantizer {
    /// Quantizes an f32 vector (assumed range [-1.0, 1.0]) to u8.
    pub fn quantize(vector: &[f32]) -> Vec<u8> {
        vector
            .iter()
            .map(|&v| {
                // Clamp to [-1, 1] then map to [0, 255]
                let clamped = v.clamp(-1.0, 1.0);
                ((clamped + 1.0) / 2.0 * 255.0).round() as u8
            })
            .collect()
    }

    /// Dequantizes a u8 vector back to f32.
    pub fn dequantize(vector: &[u8]) -> Vec<f32> {
        vector
            .iter()
            .map(|&v| (v as f32 / 255.0 * 2.0) - 1.0)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantization_roundtrip() {
        let original = vec![-1.0, 0.0, 1.0, 0.5, -0.25];
        let quantized = ScalarQuantizer::quantize(&original);
        let dequantized = ScalarQuantizer::dequantize(&quantized);

        for (o, d) in original.iter().zip(dequantized.iter()) {
            assert!(
                (o - d).abs() < 0.01,
                "Precision loss too high: {} vs {}",
                o,
                d
            );
        }
    }
}
