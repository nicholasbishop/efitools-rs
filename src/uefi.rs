use crate::guid::Guid;
use crate::serialize_u32;
use fehler::{throw, throws};
use x509_parser::pem;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("differently sized signatures")]
    DifferentlySizedSignatures,
}

pub trait Signature {
    fn guid() -> Guid;

    fn serialize_header(_buf: &mut Vec<u8>) {}
    fn header_size() -> usize {
        0
    }

    fn serialize(&self, buf: &mut Vec<u8>);
    fn serialized_size(&self) -> usize;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureX509 {
    pub der_encoded_cert: Vec<u8>,
}

impl Signature for SignatureX509 {
    fn guid() -> Guid {
        Guid::from_fields(
            0xa5c059a1,
            0x94e4,
            0x4aa7,
            &[0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
        )
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.der_encoded_cert);
    }

    fn serialized_size(&self) -> usize {
        self.der_encoded_cert.len()
    }
}

/// See "32.4.1 Signature Database"
#[derive(Clone, Debug, Eq, PartialEq)]
struct SignatureData<T: Signature> {
    owner: Guid,
    data: T,
}

impl<T: Signature> SignatureData<T> {
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.owner.serialize(buf);
        self.data.serialize(buf);
    }

    fn serialized_size(&self) -> usize {
        Guid::serialized_size() + self.data.serialized_size()
    }
}

/// See "32.4.1 Signature Database"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureList<T: Signature> {
    signatures: Vec<SignatureData<T>>,
}

impl SignatureList<SignatureX509> {
    pub fn from_x509_pem(
        pem: &[u8],
        owner: Guid,
    ) -> Option<SignatureList<SignatureX509>> {
        let der_encoded_cert = pem::pem_to_der(pem).ok()?;
        Some(SignatureList {
            signatures: vec![SignatureData {
                data: SignatureX509 {
                    der_encoded_cert: der_encoded_cert.1.contents,
                },
                owner,
            }],
        })
    }
}

impl<T: Signature> SignatureList<T> {
    pub fn new() -> SignatureList<T> {
        SignatureList {
            signatures: Vec::new(),
        }
    }

    pub fn add(&mut self, signature: T, owner: Guid) {
        self.signatures.push(SignatureData {
            data: signature,
            owner,
        });
    }

    #[throws]
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.serialized_size());
        T::guid().serialize(buf);
        // signature list size
        serialize_u32(self.serialized_size() as u32, buf);
        // signature header size
        serialize_u32(T::header_size() as u32, buf);
        // signature size
        serialize_u32(self.get_signature_size()? as u32, buf);
        // signature header
        T::serialize_header(buf);
        // signatures
        for signature in &self.signatures {
            signature.serialize(buf);
        }
    }

    #[throws]
    fn get_signature_size(&self) -> usize {
        let mut iter = self.signatures.iter();
        if let Some(first) = iter.next() {
            let size = first.serialized_size();
            for signature in iter {
                if signature.serialized_size() != size {
                    throw!(Error::DifferentlySizedSignatures);
                }
            }
            size
        } else {
            0
        }
    }

    pub fn serialized_size(&self) -> usize {
        Guid::serialized_size() +
            // signature list size
            4 +
            // signature header size
            4 +
            // signature size
            4 +
            // signature header
            T::header_size() +
            // signatures
            self
            .signatures
            .iter()
            .map(SignatureData::serialized_size)
            .sum::<usize>()
    }
}
