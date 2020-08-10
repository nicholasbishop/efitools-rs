pub mod guid;
pub mod uefi;

fn serialize_u32(val: u32, buf: &mut Vec<u8>) {
    buf.extend(&val.to_le_bytes());
}

fn serialize_u16(val: u16, buf: &mut Vec<u8>) {
    buf.extend(&val.to_le_bytes());
}
