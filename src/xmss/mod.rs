pub mod wrapper;
pub mod aggregator;

pub use wrapper::XmssWrapper;
pub use aggregator::SignatureAggregator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapper_creation() {
        let wrapper = XmssWrapper::new().expect("Failed to create wrapper");
        assert_eq!(wrapper.params().tree_height(), 10);
    }

    #[test]
    fn test_custom_params() {
        let wrapper = XmssWrapper::with_params(8, 128).expect("Failed to create wrapper");
        assert_eq!(wrapper.params().tree_height(), 8);
    }
}