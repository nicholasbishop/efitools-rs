use efitools::{guid::Guid, uefi};

#[test]
fn test_signature_list() {
    let owner: Guid = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();

    let pk_cert = include_bytes!("PK.crt");
    let sig_list = uefi::SignatureList::from_x509_pem(pk_cert, owner).unwrap();
    let mut bytes = Vec::new();
    sig_list.serialize(&mut bytes).unwrap();

    let expected_sig_list = include_bytes!("PK.esl");
    assert_eq!(bytes[..], expected_sig_list[..]);
}
