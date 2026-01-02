# AI & Machine Learning Features

Wolf Prowler integrates advanced analytics and machine learning directly into its security nodes.

## Capabilities

- **On-Node Analytics**: Low-latency data processing using `ndarray` and `polars`.
- **Classical ML**: Implementation of clustering, linear regression, and logistic regression using the `linfa` ecosystem.
- **ONNX Runtime Support**: Deploy pre-trained models for advanced threat detection via the `ort` integration.
- **Advanced Data Processing**: Seamless integration with `arrow` and `datafusion` for large-scale security telemetry analysis.

## Crate: `wolfsec` (ML Features)

- `ml-onnx`: Enables ONNX Runtime support.
- `ml-classical`: Enables classical machine learning algorithms.
- `ml-full`: Enables all ML capabilities.
