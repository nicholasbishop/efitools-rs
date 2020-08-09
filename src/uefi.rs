use fehler::throws;

pub enum Error {
    DifferentCertificateTypes,
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

/// See "32.4.1 Signature Database"
pub enum Signature {
    X509(Vec<u8>),
    // TODO there are more...
}

impl Signature {
    pub fn serialized_size(&self) -> usize {
        match self {
            //TODO
            Self::X509(_) => 0,
        }
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
pub struct SignatureData {
    pub signature_owner: Guid,
    pub signature_data: Signature,
}

impl SignatureData {
    fn serialized_size(&self) -> usize {
        Guid::serialized_size() + self.signature_data.serialized_size()
    }
}

/// See "32.4.1 Signature Database"
pub struct SignatureList {
    pub signature_type: Guid,
    pub signatures: Vec<SignatureData>,
}

impl SignatureList {
    #[throws]
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.serialized_size());
        self.signature_type.serialize(buf);
        // signature list size
        serialize_u32(self.serialized_size() as u32, buf);
        // signature header size
        serialize_u32(0, buf);
    }

    pub fn serialized_size(&self) -> usize {
        Guid::serialized_size() +
            // signature list size
            4 +
            // signature header size
            4 +
            // signature size
            4 +
            // signature header (always empty)
            0 +
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
