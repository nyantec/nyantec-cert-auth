//! # nyantec-cert-auth
//!
//! A library for parsing X.509 Client Certificates
use std::time::{SystemTime, UNIX_EPOCH};

use hyper::{header, Body, Request};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;
use x509_parser::pem::Pem;

use crate::certificate_parser::{get_email_from_dn, get_email_from_san, get_uid};

mod certificate_parser;

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("System time is before unix time")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("Error converting header value to string: {0}")]
    ToStrError(#[from] header::ToStrError),
    #[error("Missing x-ssl-client-escaped-cert header")]
    MissingHeader,
    #[error("No certificate given")]
    NoCertificate,
    #[error("SAN exists but could not be parsed")]
    InvalidSAN,
    #[error("Could not get email from certificate")]
    NoEmail,
    #[error("Certificate has no Common Name")]
    NoCommonName,
    #[error("Invalid urlencoding {0}")]
    UrlEncoding(#[from] urlencoding::FromUrlEncodingError),
    #[error("Decoding cert: {0}")]
    PEM(#[from] x509_parser::prelude::PEMError),
    #[error("Decoding cert: {0}")]
    X509(#[from] x509_parser::prelude::X509Error),
    #[error("Decoding cert: {0}")]
    Nom(#[from] x509_parser::nom::Err<x509_parser::prelude::X509Error>),
    #[error("HttpError: {0}")]
    HttpError(#[from] hyper::http::Error),
    #[error("")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Reqwest Error")]
    Reqwest(#[from] reqwest::Error),
    #[error("Hyper Error")]
    HyperError(#[from] hyper::Error),
    #[error("Supplied permissions are empty")]
    PermissionEmptyError,
    #[error("Supplied entity does not match the List of allowed entities")]
    PermissionNotMatchedError,
}

/// Custom Error Wrapper Type
pub type Result<T> = std::result::Result<T, CustomError>;

/// A struct holding essential information about a parsed X.509 Client Certificate.
#[derive(Clone, Debug, Serialize)]
pub struct Claims {
    /// Email Address (found in the *Subject Alternative Name* field).
    pub email: String,

    /// Full name of the holder of the client certificate.
    pub name: String,

    /// User id of the holder of the client certificate.
    pub uid: String,

    /// Identifies the expiration time on or after which the JWT **must not** be accepted for processing.
    ///
    /// Needed for the generation of JSON Web Tokens. See also: [RFC Section 4.1.4]
    ///
    /// [RFC Section 4.1.4]: https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.4
    pub exp: u64,

    /// Identifies the time at which the client certificate has been parsed.
    ///
    /// Needed for the generation of JSON Web Tokens. See also: [RFC Section 4.1.6]
    ///
    /// [RFC Section 4.1.6]: https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.6
    pub iat: u64,
}

/// Represents a set of permissions.
///
/// A user is allowed by the client certificate validation if the client certificate's uid matches
/// any of the `allowed_uids`.
#[derive(Clone, Debug, Deserialize)]
pub struct Permissions {
    /// Represents a list of allowed uids.
    #[serde(default)]
    pub allowed_uids: Vec<String>,
}

/// Parses a given X.509 Client Certificate and returns a Struct of parsed claims.
pub fn get_claims(req: Request<Body>) -> crate::Result<Claims> {
    let escaped_cert_str = req
        .headers()
        .get("x-ssl-client-escaped-cert")
        .ok_or(CustomError::MissingHeader)?
        .to_str()?;

    let cert_str = urlencoding::decode(escaped_cert_str)?;

    let cert_pem = Pem::iter_from_buffer(&cert_str.as_bytes())
        .next()
        .ok_or(CustomError::NoCertificate)??;

    let cert = cert_pem.parse_x509()?;

    let email = get_email_from_san(&cert)
        .transpose()
        .or_else(|| get_email_from_dn(&cert).transpose())
        .ok_or(CustomError::NoEmail)??;

    let name = cert
        .subject()
        .iter_common_name()
        .next()
        .map(|x| Ok::<_, CustomError>(x.as_str()?))
        .transpose()?
        .ok_or(CustomError::NoCommonName)?;

    let uid = get_uid(&cert)?.unwrap_or(name);

    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let exp = iat + 3600;

    Ok(Claims {
        email: email.to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        exp,
        iat,
    })
}

/// Returns Ok if and only if the user matches any of the provided allowed user ids.
pub fn is_allowed_by_uid(user: &Claims, permissions: &Permissions) -> crate::Result<()> {
    if permissions.allowed_uids.is_empty() {
        return Err(CustomError::PermissionEmptyError);
    }

    if permissions.allowed_uids.iter().any(|u| u.eq(&user.uid)) {
        Ok(())
    } else {
        Err(CustomError::PermissionNotMatchedError)
    }
}

#[cfg(test)]
mod tests {
    use crate::{is_allowed_by_uid, Claims, CustomError, Permissions};

    #[test]
    fn test_is_allowed_by_uid() {
        let user_allowed = Claims {
            email: "nya@nyantec.com".to_string(),
            name: "Some Name".to_string(),
            uid: "nya".to_string(),
            exp: 0,
            iat: 0,
        };
        let user_denied = Claims {
            email: "nyet@nyantec.com".to_string(),
            name: "Some Name".to_string(),
            uid: "nyet".to_string(),
            exp: 0,
            iat: 0,
        };

        let permissions = Permissions {
            allowed_uids: vec![user_allowed.uid.clone()],
        };
        let permissions_empty = Permissions {
            allowed_uids: vec![],
        };

        assert_eq!(
            is_allowed_by_uid(&user_allowed, &permissions).is_ok(),
            Ok::<_, CustomError>(()).is_ok()
        );
        assert_eq!(
            is_allowed_by_uid(&user_denied, &permissions).is_ok(),
            Err::<(), CustomError>(CustomError::PermissionNotMatchedError).is_ok()
        );
        assert_eq!(
            is_allowed_by_uid(&user_allowed, &permissions_empty).is_ok(),
            Err::<(), CustomError>(CustomError::PermissionEmptyError).is_ok()
        )
    }
}
