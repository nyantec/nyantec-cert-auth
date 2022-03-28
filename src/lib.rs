//! # nyantec-cert-auth
//!
//! A library for parsing X.509 Client Certificates
use std::time::{SystemTime, UNIX_EPOCH};

use custom_error::custom_error;
use hyper::{
    Body,
    header,
    Request,
};
use serde_derive::{Deserialize, Serialize};
use x509_parser::pem::Pem;

use crate::certificate_parser::{get_email_from_dn, get_email_from_san, get_uid};

mod certificate_parser;

custom_error! {pub CustomError
    SystemTimeError{source: std::time::SystemTimeError} = "System time is before unix time",
    ToStrError{source: header::ToStrError} = "Error converting header value to string: {source}",
    MissingHeader = "Missing x-ssl-client-escaped-cert header",
    NoCertificate = "No certificate given",
    InvalidSAN = "SAN exists but could not be parsed",
    NoEmail = "Could not get email from certificate",
    NoCommonName = "Certificate has no Common Name",
    UrlEncoding{source: urlencoding::FromUrlEncodingError} = "Invalid urlencoding {source}",
    PEM{source: x509_parser::prelude::PEMError} = "Decoding cert: {source}",
    X509{source: x509_parser::prelude::X509Error} = "Decoding cert: {source}",
    Nom{source: x509_parser::nom::Err<x509_parser::prelude::X509Error>} = "Decoding cert: {source}",
    HttpError{source: hyper::http::Error} = "HttpError: {source}",
    Infallible{source: std::convert::Infallible} = "",
    Reqwest{source: reqwest::Error} = "Reqwest Error",
    HyperError{source: hyper::Error} = "Hyper Error",
    PermissionEmptyError = "Supplied permissions are empty",
    PermissionNotMatchedError = "Supplied entity does not match the List of allowed entities",
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

/// Represents a set of allowed permissions.
///
/// A user is allowed by the client certificate validation if at least one of the following
/// conditions are met:
/// - The client certificate's uid matches any of the `allowed_uids`
/// - The domain part of the client certificate's email address (found in the
///   *Subject Alternative Name* field) matches any of the `allowed_emails`.
#[derive(Clone, Debug, Deserialize)]
pub struct Permissions {
    /// Represents a list of allowed uids.
    #[serde(default)]
    pub allowed_uids: Vec<String>,

    /// Represents a list of allowed email address suffixes
    ///
    /// The part **behind** the `@` will be used for comparison.
    #[serde(default)]
    pub allowed_emails: Vec<String>,
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
pub fn is_allowed_by_uid(user: &Claims, permisisons: &Permissions) -> crate::Result<()> {
    if permisisons.allowed_uids.is_empty() {
        return Err(CustomError::PermissionEmptyError);
    }

    if permisisons.allowed_uids.iter().any(|u| u.eq(&user.uid)) {
        Ok(())
    } else {
        Err(CustomError::PermissionNotMatchedError)
    }
}

/// Returns Ok if and only if the provided user matches any of the allowed email addresses.
pub fn is_allowed_by_email(user: &Claims, permissions: &Permissions) -> crate::Result<()> {
    if permissions.allowed_emails.is_empty() {
        return Err(CustomError::PermissionEmptyError);
    }

    if permissions.allowed_emails.iter().any(|email| user.email.ends_with(email)) {
        Ok(())
    } else {
        Err(CustomError::PermissionNotMatchedError)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CustomError, is_allowed_by_email, is_allowed_by_uid,
        Permissions, Claims
    };

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
            allowed_emails: vec![],
        };
        let permissions_empty = Permissions {
            allowed_uids: vec![],
            allowed_emails: vec![],
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

    #[test]
    fn test_is_allowed_by_email() {
        let user_allowed = Claims {
            email: "nya@nyantec.com".to_string(),
            name: "Some Name".to_string(),
            uid: "nya".to_string(),
            exp: 0,
            iat: 0,
        };
        let user_denied = Claims {
            email: "nyet@notallowed.com".to_string(),
            name: "Some Name".to_string(),
            uid: "nyet".to_string(),
            exp: 0,
            iat: 0,
        };

        let permissions = Permissions {
            allowed_uids: vec![],
            allowed_emails: vec![user_allowed.email.clone()],
        };
        let permissions_empty = Permissions {
            allowed_uids: vec![],
            allowed_emails: vec![],
        };

        assert_eq!(
            is_allowed_by_email(&user_allowed, &permissions).is_ok(),
            Ok::<_, CustomError>(()).is_ok()
        );
        assert_eq!(
            is_allowed_by_email(&user_denied, &permissions).is_ok(),
            Err::<(), CustomError>(CustomError::PermissionNotMatchedError).is_ok()
        );
        assert_eq!(
            is_allowed_by_uid(&user_allowed, &permissions_empty).is_ok(),
            Err::<(), CustomError>(CustomError::PermissionEmptyError).is_ok()
        )
    }
}
