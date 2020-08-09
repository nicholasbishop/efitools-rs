use anyhow::Error;
use efitools::uefi;
use fehler::throws;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use x509_parser::pem::Pem;

/// Convert an x509 certificate in PEM format to an EFI signature list
/// containing just that certificate.
#[derive(Debug, argh::FromArgs)]
struct Opt {
    /// use <guid> as the owner of the signature (if not supplied, an
    /// all-zero guid will be used)
    #[argh(switch, short = 'g')]
    guid: bool,

    #[argh(positional)]
    cert: PathBuf,

    #[argh(positional)]
    sig_list: PathBuf,
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();

    let cert = fs::read(&opt.cert)?;

    let reader = Cursor::new(cert);
    // TODO: have a PR up to make the x509-parser library errors
    // implement Error.
    let (pem, _) = Pem::read(reader).expect("failed to read PEM");
    let x509 = pem.parse_x509().expect("X.509: decoding DER failed");

    let sig_list = uefi::SignatureList {
        signature_type: uefi::CERT_X509_GUID,
        signatures: vec![uefi::SignatureData {
            // TODO
            signature_owner: uefi::Guid::from_parts(0, 0, 0, 0, 0, [0; 6]),
            signature_data: uefi::Signature::X509(vec![]),
        }],
    };

    let mut file = File::create(&opt.sig_list)?;
    let mut bytes = Vec::new();
    sig_list.serialize(&mut bytes);
    file.write_all(&bytes)?;
}
