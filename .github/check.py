import csv
from datetime import UTC, datetime
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from defusedxml.ElementTree import parse


def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


revoked_keybox_list = requests.get(
    "https://android.googleapis.com/attestation/status",
    headers={
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    },
).json()["entries"]

google_public_key = load_public_key_from_file(".github/google.pem")
aosp_ec_public_key = load_public_key_from_file(".github/aosp_ec.pem")
aosp_rsa_public_key = load_public_key_from_file(".github/aosp_rsa.pem")
knox_public_key = load_public_key_from_file(".github/knox.pem")

with open("status.csv", "w") as csvfile:
    fieldnames = [
        "File",
        "Serial number",
        "Subject",
        "Certificate within validity period",
        "Valid keychain",
        "note",
        "Serial number not found in Google's revoked keybox list",
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for kb in Path(".").glob("*.xml"):
        output = [kb.name]

        root = parse(kb).getroot()
        pem_number = int(root.find(".//NumberOfCertificates").text.strip())
        pem_certificates = [
            cert.text.strip()
            for cert in root.findall('.//Certificate[@format="pem"]')[:pem_number]
        ]
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[0].encode(), default_backend()
        )
        serial_number = hex(certificate.serial_number)[2:]
        output.append(serial_number)

        subject = ""
        for rdn in certificate.subject:
            subject += f"{rdn.oid._name}={rdn.value} | "
        subject = subject[:-3]
        output.append(subject)

        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc
        current_time = datetime.now(UTC)
        is_valid = not_valid_before <= current_time <= not_valid_after
        output.append("✅" if is_valid else "❌")

        flag = True
        for i in range(pem_number - 1):
            son_certificate = x509.load_pem_x509_certificate(
                pem_certificates[i].encode(), default_backend()
            )
            father_certificate = x509.load_pem_x509_certificate(
                pem_certificates[i + 1].encode(), default_backend()
            )

            if son_certificate.issuer != father_certificate.subject:
                flag = False
                break
            signature = son_certificate.signature
            signature_algorithm = son_certificate.signature_algorithm_oid._name
            tbs_certificate = son_certificate.tbs_certificate_bytes
            public_key = father_certificate.public_key()
            try:
                match signature_algorithm:
                    case "sha256WithRSAEncryption" | "ecdsa-with-SHA256":
                        hash_algorithm = hashes.SHA256()
                    case "sha1WithRSAEncryption" | "ecdsa-with-SHA1":
                        hash_algorithm = hashes.SHA1()
                    case "sha384WithRSAEncryption" | "ecdsa-with-SHA384":
                        hash_algorithm = hashes.SHA384()
                    case "sha512WithRSAEncryption" | "ecdsa-with-SHA512":
                        hash_algorithm = hashes.SHA512()

                if signature_algorithm.endswith("WithRSAEncryption"):
                    padding_algorithm = padding.PKCS1v15()
                    public_key.verify(
                        signature, tbs_certificate, padding_algorithm, hash_algorithm
                    )
                else:
                    padding_algorithm = ec.ECDSA(hash_algorithm)
                    public_key.verify(signature, tbs_certificate, padding_algorithm)
            except Exception as e:
                flag = False
                break
        output.append("✅" if flag else "❌")

        root_certificate = x509.load_pem_x509_certificate(
            pem_certificates[-1].encode(), default_backend()
        )
        root_public_key = root_certificate.public_key()
        if compare_keys(root_public_key, google_public_key):
            output.append("✅ Google hardware attestation root certificate")
        elif compare_keys(root_public_key, aosp_ec_public_key):
            output.append("🟡 AOSP software attestation root certificate (EC)")
        elif compare_keys(root_public_key, aosp_rsa_public_key):
            output.append("🟡 AOSP software attestation root certificate (RSA)")
        elif compare_keys(root_public_key, knox_public_key):
            output.append("✅ Samsung Knox attestation root certificate")
        else:
            output.append("❌ Unknown root certificate")

        output.append("✅" if not revoked_keybox_list.get(serial_number, None) else "❌")
        writer.writerow(dict(zip(fieldnames, output)))
