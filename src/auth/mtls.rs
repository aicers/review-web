use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use review_database as database;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde::de::Error as SerdeError;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
};
use x509_parser::prelude::{X509Certificate, parse_x509_certificate};

#[derive(Debug, thiserror::Error)]
pub enum MtlsAuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("JWT error: {0}")]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
}

/// Represents the identity extracted from a client certificate's DNS SAN.
///
/// SAN format: `<instance>.<service>.<host>.<domain>`
/// Example: `001.web-app.node-01.customer.internal`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsIdentity {
    pub instance: String,
    pub service: String,
    pub host: String,
    pub domain: String,
}

/// Validates a client certificate and extracts its identity.
///
/// Implementations live in the `review` crate and are injected at runtime,
/// following the same pattern as [`crate::backend::CertManager`].
pub trait MtlsAuthenticator: Send + Sync {
    /// Validates the certificate and returns the parsed identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate cannot be parsed or does not meet
    /// the expected identity constraints (e.g., missing or invalid DNS SAN).
    fn authenticate(&self, cert: &CertificateDer<'static>) -> Result<MtlsIdentity, MtlsAuthError>;
}

const ERR_INVALID_JWT_HEADER: &str = "Invalid JWT header";
const ERR_MISSING_EC_PARAMS: &str = "Missing EC curve parameters";
const ERR_JWT_ALG_RSA_MISMATCH: &str = "JWT algorithm does not match RSA key";
const ERR_JWT_ALG_EC_MISMATCH: &str = "JWT algorithm does not match EC key";
const ERR_UNSUPPORTED_EC_CURVE: &str = "Unsupported EC curve";
const ERR_UNSUPPORTED_KEY_TYPE: &str = "Unsupported client certificate key type";
const ERR_INVALID_EC_KEY: &str = "Invalid EC key";
const ERR_INVALID_EC_ENCODING: &str = "Invalid EC public key encoding";
const ERR_MISSING_CUSTOMER_IDS: &str = "Missing customer_ids claim for non-admin role";

#[derive(Debug, serde::Deserialize)]
struct ContextClaims {
    #[serde(deserialize_with = "deserialize_role")]
    role: database::Role,
    customer_ids: Option<Vec<u32>>,
    exp: i64,
}

/// Validates a context JWT using the client certificate public key.
///
/// # Errors
///
/// Returns an error if the JWT is invalid, does not match the certificate key, or lacks claims.
pub fn validate_context_jwt(
    token: &str,
    cert: &CertificateDer<'static>,
) -> Result<(database::Role, Option<Vec<u32>>), MtlsAuthError> {
    let cert = parse_cert(cert)?;
    let header = decode_header(token)
        .map_err(|e| MtlsAuthError::InvalidToken(format!("{ERR_INVALID_JWT_HEADER}: {e}")))?;

    let (alg, key) = decoding_key_from_cert(&cert, header.alg)?;
    let mut validation = Validation::new(alg);
    validation.validate_exp = true;

    let token_data =
        decode::<ContextClaims>(token, &key, &validation).map_err(MtlsAuthError::JsonWebToken)?;
    let exp = token_data.claims.exp;
    // Keep exp in ContextClaims because jsonwebtoken requires it when Validation::validate_exp is
    // true; we still read it to avoid clippy dead-code while the expiration check is already
    // handled by decode().
    debug_assert!(exp > 0, "exp must be positive");
    let role = token_data.claims.role;
    let customer_ids = token_data.claims.customer_ids;

    if customer_ids.is_none() && role != database::Role::SystemAdministrator {
        return Err(MtlsAuthError::InvalidToken(
            ERR_MISSING_CUSTOMER_IDS.to_string(),
        ));
    }

    Ok((role, customer_ids))
}

fn parse_cert<'a>(cert: &'a CertificateDer<'static>) -> Result<X509Certificate<'a>, MtlsAuthError> {
    let (_, cert) = parse_x509_certificate(cert.as_ref())
        .map_err(|e| MtlsAuthError::InvalidToken(format!("Invalid client certificate: {e:?}")))?;
    Ok(cert)
}

fn decoding_key_from_cert(
    cert: &X509Certificate<'_>,
    header_alg: Algorithm,
) -> Result<(Algorithm, DecodingKey), MtlsAuthError> {
    let pub_key = cert.public_key();
    let alg_oid = &pub_key.algorithm.algorithm;

    if alg_oid == &OID_PKCS1_RSAENCRYPTION {
        let jwt_alg = match header_alg {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => header_alg,
            _ => {
                return Err(MtlsAuthError::InvalidToken(
                    ERR_JWT_ALG_RSA_MISMATCH.to_string(),
                ));
            }
        };
        let key = DecodingKey::from_rsa_der(&pub_key.subject_public_key.data);
        return Ok((jwt_alg, key));
    }

    if alg_oid == &OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve_oid = pub_key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|params| params.as_oid().ok())
            .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_EC_PARAMS.to_string()))?;
        let (curve_alg, coord_len) = if curve_oid == OID_EC_P256 {
            (Algorithm::ES256, 32)
        } else if curve_oid == OID_NIST_EC_P384 {
            (Algorithm::ES384, 48)
        } else {
            return Err(MtlsAuthError::InvalidToken(
                ERR_UNSUPPORTED_EC_CURVE.to_string(),
            ));
        };

        if header_alg != curve_alg {
            return Err(MtlsAuthError::InvalidToken(
                ERR_JWT_ALG_EC_MISMATCH.to_string(),
            ));
        }

        let (x, y) = ec_point_to_components(&pub_key.subject_public_key.data, coord_len)?;
        let key = DecodingKey::from_ec_components(&x, &y)
            .map_err(|e| MtlsAuthError::InvalidToken(format!("{ERR_INVALID_EC_KEY}: {e}")))?;
        return Ok((curve_alg, key));
    }

    Err(MtlsAuthError::InvalidToken(
        ERR_UNSUPPORTED_KEY_TYPE.to_string(),
    ))
}

fn ec_point_to_components(
    point: &[u8],
    coord_len: usize,
) -> Result<(String, String), MtlsAuthError> {
    if point.len() != 1 + (2 * coord_len) || point.first() != Some(&0x04) {
        return Err(MtlsAuthError::InvalidToken(
            ERR_INVALID_EC_ENCODING.to_string(),
        ));
    }

    let x = point
        .get(1..=coord_len)
        .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_INVALID_EC_ENCODING.to_string()))?;
    let y = point
        .get((1 + coord_len)..)
        .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_INVALID_EC_ENCODING.to_string()))?;
    let x = URL_SAFE_NO_PAD.encode(x);
    let y = URL_SAFE_NO_PAD.encode(y);
    Ok((x, y))
}

fn deserialize_role<'de, D>(deserializer: D) -> Result<database::Role, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    database::Role::from_str(&raw).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use review_database as database;
    use rustls::pki_types::CertificateDer;
    use serde::Serialize;
    use serde_json::json;

    use super::{
        Algorithm, ERR_JWT_ALG_EC_MISMATCH, ERR_MISSING_CUSTOMER_IDS, MtlsAuthError,
        validate_context_jwt,
    };

    const CUSTOMER_ID: u32 = 42;
    const ROLE: &str = "System Administrator";
    const NON_ADMIN_ROLE: &str = "Security Administrator";
    const SERVICE_DNS: &str = "edge.aice-web-next.example.com";
    const HEADER_ALG_RS256: &str = "RS256";
    const HEADER_TYP_JWT: &str = "JWT";
    const SIGNATURE_PLACEHOLDER: &str = "signature";

    #[derive(Serialize)]
    struct TestClaims<'a> {
        role: &'a str,
        customer_ids: Option<Vec<u32>>,
        exp: i64,
    }

    #[derive(Serialize)]
    struct MissingCustomerIdsClaims<'a> {
        role: &'a str,
        exp: i64,
    }

    fn build_ec_cert(dns_name: &str) -> (CertificateDer<'static>, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("PKCS_ECDSA_P256_SHA256 is supported in tests");
        let params = CertificateParams::new(vec![dns_name.to_string()])
            .expect("test SANs are valid DNS names");
        let cert = params
            .self_signed(&key_pair)
            .expect("generated key pair and params are valid for rcgen");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = key_pair.serialize_der();
        (cert_der, key_der)
    }

    fn sign_token(exp: i64, customer_ids: Option<Vec<u32>>, key_der: &[u8]) -> String {
        let claims = TestClaims {
            role: ROLE,
            customer_ids,
            exp,
        };
        let header = Header::new(Algorithm::ES256);
        encode(&header, &claims, &EncodingKey::from_ec_der(key_der))
            .expect("key_der was generated by rcgen and matches ES256")
    }

    fn unsigned_token(exp: i64) -> String {
        let header = json!({
            "alg": HEADER_ALG_RS256,
            "typ": HEADER_TYP_JWT
        });
        let claims = json!({
            "role": ROLE,
            "customer_ids": [CUSTOMER_ID],
            "exp": exp
        });
        let header = super::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("header is a valid JSON object"));
        let claims = super::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("claims are a valid JSON object"));
        let signature = super::URL_SAFE_NO_PAD.encode(SIGNATURE_PLACEHOLDER.as_bytes());
        format!("{header}.{claims}.{signature}")
    }

    #[test]
    fn context_jwt_validates_role_and_customer_ids() {
        let (cert, key_der) = build_ec_cert(SERVICE_DNS);
        let exp = (Utc::now() + Duration::minutes(5)).timestamp();
        let token = sign_token(exp, Some(vec![CUSTOMER_ID]), &key_der);
        let (role, customer_ids) =
            validate_context_jwt(&token, &cert).expect("token is signed by the test key");
        assert_eq!(role, database::Role::SystemAdministrator);
        assert_eq!(customer_ids, Some(vec![CUSTOMER_ID]));
    }

    #[test]
    fn context_jwt_rejects_expired_token() {
        let (cert, key_der) = build_ec_cert(SERVICE_DNS);
        let exp = (Utc::now() - Duration::minutes(5)).timestamp();
        let token = sign_token(exp, Some(vec![CUSTOMER_ID]), &key_der);
        let err = validate_context_jwt(&token, &cert).expect_err("token is already expired");
        match err {
            MtlsAuthError::InvalidToken(_) | MtlsAuthError::JsonWebToken(_) => {}
        }
    }

    #[test]
    fn context_jwt_rejects_missing_customer_ids_for_non_admin() {
        let (cert, key_der) = build_ec_cert(SERVICE_DNS);
        let exp = (Utc::now() + Duration::minutes(5)).timestamp();
        let claims = TestClaims {
            role: NON_ADMIN_ROLE,
            customer_ids: None,
            exp,
        };
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &EncodingKey::from_ec_der(&key_der))
            .expect("key_der was generated by rcgen and matches ES256");

        let err = validate_context_jwt(&token, &cert).expect_err("non-admins require customer_ids");
        match err {
            MtlsAuthError::InvalidToken(msg) => {
                assert_eq!(msg, ERR_MISSING_CUSTOMER_IDS);
            }
            MtlsAuthError::JsonWebToken(_) => {
                panic!("missing customer_ids should be detected after JWT decoding");
            }
        }
    }

    #[test]
    fn context_jwt_allows_missing_customer_ids_for_admin() {
        let (cert, key_der) = build_ec_cert(SERVICE_DNS);
        let exp = (Utc::now() + Duration::minutes(5)).timestamp();
        let claims = MissingCustomerIdsClaims { role: ROLE, exp };
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &EncodingKey::from_ec_der(&key_der))
            .expect("key_der was generated by rcgen and matches ES256");

        let (role, customer_ids) =
            validate_context_jwt(&token, &cert).expect("admin can omit customer_ids");
        assert_eq!(role, database::Role::SystemAdministrator);
        assert_eq!(customer_ids, None);
    }

    #[test]
    fn context_jwt_rejects_alg_mismatch() {
        let (cert, _key_der) = build_ec_cert(SERVICE_DNS);
        let exp = (Utc::now() + Duration::minutes(5)).timestamp();
        let token = unsigned_token(exp);
        let err =
            validate_context_jwt(&token, &cert).expect_err("token header uses RS256 with EC cert");
        match err {
            MtlsAuthError::InvalidToken(msg) => {
                assert_eq!(msg, ERR_JWT_ALG_EC_MISMATCH);
            }
            MtlsAuthError::JsonWebToken(_) => {
                panic!("alg mismatch should be detected before JWT decoding");
            }
        }
    }
}
