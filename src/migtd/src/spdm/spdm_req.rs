// Spdm Requester is the MigTD src side implementation.

use async_trait::async_trait;
use spdmlib::{common::{self, SecuredMessageVersion, SpdmConfigInfo, SpdmProvisionInfo}, config, error::{SpdmResult, SpdmStatus, SPDM_STATUS_RECEIVE_FAIL, SPDM_STATUS_SEND_FAIL}, protocol::{SpdmAeadAlgo, SpdmAlgoOtherParams, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo, SpdmKeyScheduleAlgo, SpdmMeasurementSpecification, SpdmReqAsymAlgo, SpdmRequestCapabilityFlags, SpdmVersion}, requester::RequesterContext, responder::ResponderContext};
use async_io::{AsyncRead, AsyncWrite};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use spdmlib::common::SpdmDeviceIo;
use log::info;

use crate::spdm::vmcall_msg::VmCallTransportEncap;

pub fn spdm_requester<T: SpdmDeviceIo + Send + Sync + 'static> (stream: T) -> Result<RequesterContext, SpdmStatus> {
    info!("spdm_requester init\n");
    let device_io = Arc::new(Mutex::new(stream));

    let req_capabilities =
        SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        | SpdmRequestCapabilityFlags::CHUNK_CAP;

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            None,
            None,
            Some(SpdmVersion::SpdmVersion12),
            None,
        ],
        req_capabilities,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::default(),
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
        data_transfer_size: config::SPDM_DATA_TRANSFER_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        secure_spdm_version: [
            None,
            None,
            Some(SecuredMessageVersion::try_from(0x12u8).unwrap()),
        ],
        ..Default::default()
    };

    let provision_info = SpdmProvisionInfo {
        ..Default::default()
    };

    // Create a transport layer
    let transport_encap = Arc::new(Mutex::new(VmCallTransportEncap {}));

    // Initialize the RequesterContext
    let requester_context = RequesterContext::new(device_io, transport_encap, config_info, provision_info);

    Ok(requester_context)
}

pub fn spdm_responder<T: SpdmDeviceIo + Send + Sync + 'static> (stream: T) -> Result<ResponderContext, SpdmStatus> {
    info!("spdm_responder init\n");
    let device_io = Arc::new(Mutex::new(stream));

    let req_capabilities =
        SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        | SpdmRequestCapabilityFlags::CHUNK_CAP;

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            None,
            None,
            Some(SpdmVersion::SpdmVersion12),
            None,
        ],
        req_capabilities,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::default(),
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
        data_transfer_size: config::SPDM_DATA_TRANSFER_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        secure_spdm_version: [
            None,
            None,
            Some(SecuredMessageVersion::try_from(0x12u8).unwrap()),
        ],
        ..Default::default()
    };

    let provision_info = SpdmProvisionInfo {
        ..Default::default()
    };

    // Create a transport layer
    let transport_encap = Arc::new(Mutex::new(VmCallTransportEncap {}));

    // Initialize the RequesterContext
    let responder_context = ResponderContext::new(device_io, transport_encap, config_info, provision_info);

    Ok(responder_context)
}