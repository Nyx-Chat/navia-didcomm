use base64::prelude::*;

use crate::pqc_jws::{Algorithm, JWS};
use crate::{
    algorithms::SignAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    utils::{crypto::AsKnownKeyPair, did::did_or_url},
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unpack_sign<'dr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    _opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let jws_json = msg;

    let jws = match JWS::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    };

    let mut buf = vec![];
    let parsed_jws = jws.parse(&mut buf)?;

    if parsed_jws.protected.len() != 1 {
        Err(err_msg(
            ErrorKind::Malformed,
            "Wrong amount of signatures for jws",
        ))?
    }

    let alg = &parsed_jws
        .protected
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first protected header",
            )
        })?
        .alg;

    let signer_kid = &parsed_jws
        .jws
        .signatures
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first signature",
            )
        })?
        .header
        .kid;

    let (signer_did, signer_url) = did_or_url(signer_kid);

    if signer_url.is_none() {
        Err(err_msg(
            ErrorKind::Malformed,
            "Signer key can't be resolved to key agreement",
        ))?
    }

    let signer_ddoc = did_resolver
        .resolve(signer_did)
        .await
        .context("Unable resolve signer did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?;

    let signer_kid = signer_ddoc
        .authentication
        .iter()
        .find(|&k| k.as_str() == signer_kid)
        .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "Signer kid not found in did"))?
        .as_str();

    let signer_key = signer_ddoc
        .verification_method
        .iter()
        .find(|&vm| vm.id == signer_kid)
        .ok_or_else(|| {
            err_msg(
                ErrorKind::DIDUrlNotFound,
                "Sender verification method not found in did",
            )
        })?;

    let valid = match alg {
        Algorithm::MlDsa65 => {
            metadata.sign_alg = Some(SignAlg::MlDsa65);

            let signer_key = signer_key
                .as_ml_dsa_65()
                .kind(ErrorKind::InvalidState, "Unable instantiate signer key")?;

            let signature_bytes = BASE64_URL_SAFE_NO_PAD
                .decode(&parsed_jws.jws.signatures[0].signature)
                .kind(ErrorKind::InvalidState, "Unable to decode signature")?;

            let signing_input = format!(
                "{}.{}",
                parsed_jws.jws.signatures[0].protected, parsed_jws.jws.payload
            );

            crate::pqc_jws::verify_ml_dsa_65(
                &signature_bytes,
                signing_input.as_bytes(),
                signer_key.public_key(),
            )
            .kind(
                ErrorKind::InvalidState,
                "Unable verify ML-DSA-65 sign envelope",
            )?
        }
        Algorithm::MlDsa87 => {
            metadata.sign_alg = Some(SignAlg::MlDsa87);

            let signer_key = signer_key
                .as_ml_dsa_87()
                .kind(ErrorKind::InvalidState, "Unable instantiate signer key")?;

            let signature_bytes = BASE64_URL_SAFE_NO_PAD
                .decode(&parsed_jws.jws.signatures[0].signature)
                .kind(ErrorKind::InvalidState, "Unable to decode signature")?;

            let signing_input = format!(
                "{}.{}",
                parsed_jws.jws.signatures[0].protected, parsed_jws.jws.payload
            );

            crate::pqc_jws::verify_ml_dsa_87(
                &signature_bytes,
                signing_input.as_bytes(),
                signer_key.public_key(),
            )
            .kind(
                ErrorKind::InvalidState,
                "Unable verify ML-DSA-87 sign envelope",
            )?
        }

        Algorithm::Other => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported signature algorithm",
        ))?,
    };

    if !valid {
        Err(err_msg(ErrorKind::Malformed, "Wrong signature"))?
    }

    // Decode JWS payload with proper error context
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(parsed_jws.jws.payload)
        .kind(ErrorKind::Malformed, "Signed payloa is invalid base64")?;

    let payload =
        String::from_utf8(payload).kind(ErrorKind::Malformed, "Signed payload is invalid utf8")?;

    metadata.authenticated = true;
    metadata.non_repudiation = true;
    metadata.sign_from = Some(signer_kid.into());
    metadata.signed_message = Some(jws_json.into());

    Ok(Some(payload))
}
