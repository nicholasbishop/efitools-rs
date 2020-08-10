use anyhow::Error;
use efitools::guid::Guid;
use efitools::uefi;
use fehler::throws;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Convert an x509 certificate in PEM format to an EFI signature list
/// containing just that certificate.
#[derive(Debug, argh::FromArgs)]
struct Opt {
    /// use <guid> as the owner of the signature (defaults to an
    /// all-zero guid)
    #[argh(option, default = "Guid::nil()")]
    owner: Guid,

    #[argh(positional)]
    cert: PathBuf,

    #[argh(positional)]
    sig_list: PathBuf,
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();

    let pem = fs::read(&opt.cert)?;
    let sig_list = uefi::SignatureList::from_x509_pem(&pem, opt.owner)
        .expect("invalid cert");

    let mut file = File::create(&opt.sig_list)?;
    let mut bytes = Vec::new();
    sig_list.serialize(&mut bytes)?;
    file.write_all(&bytes)?;
}
