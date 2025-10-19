#[cfg(feature = "spdm_attestation")]
mod spdm_req;
#[cfg(feature = "spdm_attestation")]
mod spdm_rsp;
#[cfg(feature = "spdm_attestation")]
mod spdm_vdm;
#[cfg(feature = "spdm_attestation")]
mod vmcall_msg;

#[cfg(feature = "spdm_attestation")]
use alloc::vec::Vec;
#[cfg(feature = "spdm_attestation")]
use core::time::Duration;

#[cfg(feature = "spdm_attestation")]
use async_io::AsyncRead;
#[cfg(feature = "spdm_attestation")]
use async_io::AsyncWrite;
#[cfg(feature = "spdm_attestation")]
use crypto::hash::digest_sha384;
#[cfg(feature = "spdm_attestation")]
pub use spdm_req::spdm_requester;
#[cfg(feature = "spdm_attestation")]
pub use spdm_req::spdm_requester_transfer_msk;
#[cfg(feature = "spdm_attestation")]
pub use spdm_rsp::spdm_responder;

#[cfg(feature = "spdm_attestation")]
pub use spdm_rsp::*;
#[cfg(feature = "spdm_attestation")]
pub use spdm_vdm::*;

#[cfg(feature = "spdm_attestation")]
use crate::migration::MigrationResult;

#[cfg(feature = "spdm_attestation")]
const SPDM_TIMEOUT: Duration = Duration::from_secs(60); // 60 seconds

#[cfg(feature = "spdm_attestation")]
pub struct MigtdTransport<T: AsyncRead + AsyncWrite + Unpin> {
    pub transport: T,
}
#[cfg(feature = "spdm_attestation")]
unsafe impl<T: AsyncRead + AsyncWrite + Unpin> Send for MigtdTransport<T> {}

#[cfg(feature = "spdm_attestation")]
pub fn gen_quote_spdm(report_data: &[u8]) -> Result<Vec<u8>, MigrationResult> {
    let hash = digest_sha384(report_data)?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&additional_data)?;

    let res = attestation::get_quote(td_report.as_bytes()).unwrap();
    Ok(res)
}
