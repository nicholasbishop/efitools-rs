use anyhow::Error;
use efitools::uefi;
use fehler::throws;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use x509_parser::pem;

/// Convert an x509 certificate in PEM format to an EFI signature list
/// containing just that certificate.
#[derive(Debug, argh::FromArgs)]
struct Opt {
    /// use <guid> as the owner of the signature (defaults to an
    /// all-zero guid)
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

    let pem = fs::read(&opt.cert)?;
    // TODO: have a PR up to make the x509-parser library errors
    // implement Error.
    let der_encoded_cert =
        pem::pem_to_der(&pem).expect("failed to convert PEM to DER");

    let mut sig_list = uefi::SignatureList::new();
    sig_list.add(
        uefi::SignatureX509 {
            der_encoded_cert: der_encoded_cert.1.contents,
        },
        // TODO
        uefi::Guid::zero(),
    );

    let mut file = File::create(&opt.sig_list)?;
    let mut bytes = Vec::new();
    sig_list.serialize(&mut bytes)?;
    file.write_all(&bytes)?;
}
