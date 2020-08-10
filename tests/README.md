# Test files

## Generate PK.key and PK.cert

    openssl req -new -x509 -newkey rsa:2048 -subj "/CN=PK/" -keyout PK.key -out PK.crt -days 3650 -nodes -sha256

## Generate PK.esl

This depends on https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git

    cert-to-efi-sig-list -g 00112233-4455-6677-8899-aabbccddeeff PK.crt PK.esl
