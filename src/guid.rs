use crate::{serialize_u16, serialize_u32};
use fehler::throws;
use std::str::FromStr;
use uuid::{Error, Uuid};

/// EFI Globally Unique Identifier
///
/// See "Appendix A - GUID and Time Formats"
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Guid(Uuid);

impl Guid {
    pub fn from_fields(d1: u32, d2: u16, d3: u16, d4: &[u8; 8]) -> Guid {
        // OK to unwrap here since we know the length of d4 is correct
        Guid(Uuid::from_fields_le(d1, d2, d3, d4).unwrap())
    }

    pub const fn nil() -> Guid {
        Guid(Uuid::nil())
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.reserve(Self::serialized_size());
        let (a, b, c, d) = self.0.to_fields_le();

        serialize_u32(a, buf);
        serialize_u16(b, buf);
        serialize_u16(c, buf);
        buf.extend(d);
    }

    pub const fn serialized_size() -> usize {
        16
    }
}

impl FromStr for Guid {
    type Err = Error;

    #[throws]
    fn from_str(s: &str) -> Self {
        Guid(Uuid::from_str(s)?)
    }
}
