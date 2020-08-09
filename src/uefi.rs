use fehler::{throw, throws};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("differently sized signatures")]
    DifferentlySizedSignatures,
}

/// EFI Globally Unique Identifier
///
/// See "Appendix A - GUID and Time Formats"
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C, packed)]
pub struct Guid {
    /// The low field of the timestamp.
    time_low: u32,

    /// The middle field of the timestamp.
    time_mid: u16,

    /// The high field of the timestamp multiplexed with the version
    /// number.
    time_high_and_version: u16,

    /// The high field of the clock sequence multiplexed with the
    /// variant.
    clock_seq_high_and_reserved: u8,

    /// The low field of the clock sequence.
    clock_seq_low: u8,
    /// The spatially unique node identifier. This can be based on any
    /// IEEE 802 address obtained from a network card. If no network
    /// card exists in the system, a cryptographic-quality random
    /// number can be used.
    node: [u8; 6],
}

impl Guid {
    pub const fn from_parts(
        time_low: u32,
        time_mid: u16,
        time_high_and_version: u16,
        clock_seq_high_and_reserved: u8,
        clock_seq_low: u8,
        node: [u8; 6],
    ) -> Guid {
        Guid {
            time_low,
            time_mid,
            time_high_and_version,
            clock_seq_high_and_reserved,
            clock_seq_low,
            node,
        }
    }

    pub const fn zero() -> Guid {
        Self::from_parts(0, 0, 0, 0, 0, [0; 6])
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.reserve(Self::serialized_size());
        serialize_u32(self.time_low, buf);
        serialize_u16(self.time_mid, buf);
        serialize_u16(self.time_high_and_version, buf);
        buf.push(self.clock_seq_high_and_reserved);
        buf.push(self.clock_seq_low);
        buf.extend(&self.node);
    }

    pub const fn serialized_size() -> usize {
        16
    }
}

pub trait Signature {
    const GUID: Guid;

    fn serialize_header(_buf: &mut Vec<u8>) {}
    fn header_size() -> usize {
        0
    }

    fn serialize(&self, buf: &mut Vec<u8>);
    fn serialized_size(&self) -> usize;
}

pub struct SignatureX509 {
    pub der_encoded_cert: Vec<u8>,
}

impl Signature for SignatureX509 {
    const GUID: Guid = Guid::from_parts(
        0xa5c059a1,
        0x94e4,
        0x4aa7,
        0x87,
        0xb5,
        [0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
    );

    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.der_encoded_cert);
    }

    fn serialized_size(&self) -> usize {
        self.der_encoded_cert.len()
    }
}

/// See "32.4.1 Signature Database"
pub const CERT_X509_GUID: Guid = Guid::from_parts(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    0x87,
    0xb5,
    [0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);

/// See "32.4.1 Signature Database"
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
pub struct SignatureList<T: Signature> {
    signatures: Vec<SignatureData<T>>,
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
        T::GUID.serialize(buf);
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

fn serialize_u32(val: u32, buf: &mut Vec<u8>) {
    buf.extend(&val.to_le_bytes());
}

fn serialize_u16(val: u16, buf: &mut Vec<u8>) {
    buf.extend(&val.to_le_bytes());
}
