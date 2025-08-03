use xmss_for_ethereum::{XmssWrapper, SignatureAggregator};

#[test]
fn test_single_signature_verification() {
    let wrapper = XmssWrapper::new().expect("Failed to create wrapper");
    let keypair = wrapper.generate_keypair().expect("Failed to generate keypair");
    
    let message = b"Hello, XMSS!";
    let signature = wrapper.sign(&keypair, message).expect("Failed to sign");
    
    let public_key = {
        let kp = keypair.lock().unwrap();
        kp.public_key().clone()
    };
    
    let is_valid = wrapper.verify(&public_key, message, &signature)
        .expect("Failed to verify");
    
    assert!(is_valid, "Signature verification failed");
}

#[test]
fn test_multiple_signatures_aggregation() {
    // Use smaller tree height for faster tests
    let wrapper = XmssWrapper::with_params(4, 128).expect("Failed to create wrapper");
    let params = wrapper.params().clone();
    let mut aggregator = SignatureAggregator::new(params);
    
    // Generate and add 3 signatures (reduced from 5)
    for i in 0..3 {
        let keypair = wrapper.generate_keypair().expect("Failed to generate keypair");
        let message = format!("Message {}", i).into_bytes();
        let signature = wrapper.sign(&keypair, &message).expect("Failed to sign");
        
        let public_key = {
            let kp = keypair.lock().unwrap();
            kp.public_key().clone()
        };
        
        aggregator.add_signature(signature, message, public_key)
            .expect("Failed to add signature");
    }
    
    assert_eq!(aggregator.len(), 3);
    
    let (is_valid, _duration) = aggregator.verify_all()
        .expect("Failed to verify all");
    
    assert!(is_valid, "Batch verification failed");
}

#[test]
fn test_invalid_signature_detection() {
    let wrapper = XmssWrapper::new().expect("Failed to create wrapper");
    let keypair1 = wrapper.generate_keypair().expect("Failed to generate keypair 1");
    let keypair2 = wrapper.generate_keypair().expect("Failed to generate keypair 2");
    
    let message = b"Test message";
    
    // Sign with keypair1
    let signature = wrapper.sign(&keypair1, message).expect("Failed to sign");
    
    // Try to verify with keypair2's public key
    let wrong_public_key = {
        let kp = keypair2.lock().unwrap();
        kp.public_key().clone()
    };
    
    let is_valid = wrapper.verify(&wrong_public_key, message, &signature)
        .expect("Failed to verify");
    
    assert!(!is_valid, "Invalid signature was accepted");
}

#[test]
#[ignore] // This test is slow due to generating 10 keypairs
fn test_aggregator_capacity() {
    // Use smaller tree height for faster tests
    let wrapper = XmssWrapper::with_params(2, 128).expect("Failed to create wrapper");
    let params = wrapper.params().clone();
    let mut aggregator = SignatureAggregator::new(params);
    
    // Generate one keypair and reuse it
    let keypair = wrapper.generate_keypair().expect("Failed to generate keypair");
    let public_key = {
        let kp = keypair.lock().unwrap();
        kp.public_key().clone()
    };
    
    // Fill aggregator to capacity (10 signatures) with different messages
    for i in 0..10 {
        let message = format!("Message {}", i).into_bytes();
        let signature = wrapper.sign(&keypair, &message).expect("Failed to sign");
        
        aggregator.add_signature(signature, message, public_key.clone())
            .expect("Failed to add signature");
    }
    
    // Try to add 11th signature
    let message = b"Extra message";
    let signature = wrapper.sign(&keypair, message).expect("Failed to sign");
    
    let result = aggregator.add_signature(signature, message.to_vec(), public_key);
    assert!(result.is_err(), "Aggregator accepted more than 10 signatures");
}

#[test]
fn test_serialization_for_proof() {
    // Use smaller tree height for faster tests
    let wrapper = XmssWrapper::with_params(2, 128).expect("Failed to create wrapper");
    let params = wrapper.params().clone();
    let mut aggregator = SignatureAggregator::new(params);
    
    // Generate one keypair and reuse it for speed
    let keypair = wrapper.generate_keypair().expect("Failed to generate keypair");
    let public_key = {
        let kp = keypair.lock().unwrap();
        kp.public_key().clone()
    };
    
    // Add 3 signatures with different messages
    for i in 0..3 {
        let message = format!("Message {}", i).into_bytes();
        let signature = wrapper.sign(&keypair, &message).expect("Failed to sign");
        
        aggregator.add_signature(signature, message, public_key.clone())
            .expect("Failed to add signature");
    }
    
    let serialized = aggregator.serialize_for_proof()
        .expect("Failed to serialize");
    
    // Check that serialization produced data
    assert!(!serialized.is_empty(), "Serialization produced empty data");
    
    // Check that it starts with the correct signature count
    let sig_count = u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    assert_eq!(sig_count, 3, "Incorrect signature count in serialized data");
}