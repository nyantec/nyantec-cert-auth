use der_parser::oid;
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
};

use crate::CustomError;

/// Retrieves the email address from the *Subject Alternative Name* (SAN) field.
pub(crate) fn get_email_from_san<'a>(cert: &'a X509Certificate) -> crate::Result<Option<&'a str>> {
    cert.extensions()
        .get(&oid!(2.5.29 .17))
        .and_then(|r| {
            if let ParsedExtension::SubjectAlternativeName(san) = r.parsed_extension() {
                // We got the SAN, maybe it has an email
                san.general_names
                    .iter()
                    .filter_map(|x| {
                        if let GeneralName::RFC822Name(email) = x {
                            Some(Ok(email.to_owned()))
                        } else {
                            None
                        }
                    })
                    .next()
            } else {
                // This is supposed to be a SAN, but we can't parse it
                Some(Err(CustomError::InvalidSAN))
            }
        })
        .transpose()
        .map(|x| x)
}

/// Retrieves the email address from the dn.
pub(crate) fn get_email_from_dn<'a>(cert: &'a X509Certificate) -> crate::Result<Option<&'a str>> {
    cert.subject()
        .iter_email()
        .next()
        .map(|x| Ok(x.as_str()?))
        .transpose()
}

/// Retrieves the uid from the certificate.
pub(crate) fn get_uid<'a>(cert: &'a X509Certificate) -> crate::Result<Option<&'a str>> {
    cert.subject()
        .iter_by_oid(&oid!(0.9.2342 .19200300 .100 .1 .1))
        .next()
        .map(|x| Ok(x.as_str()?))
        .transpose()
}
