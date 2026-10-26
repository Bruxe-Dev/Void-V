#include "pki_engine.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sodium.h>

#include <array>
#include <climits>
#include <memory>
#include <string>

namespace
{
    constexpr std::uint64_t MAX_CA_VALIDITY_DAYS = 3650;
    constexpr std::uint64_t MAX_LEAF_VALIDITY_DAYS = 825;

    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using KeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BigNumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
    using ExtensionPtr = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;

    bool validCommonName(std::string_view common_name) noexcept
    {
        if (common_name.empty() || common_name.size() > 128 ||
            common_name.find('\0') != std::string_view::npos)
        {
            return false;
        }
        for (const unsigned char c : common_name)
        {
            if (c < 0x20U || c == 0x7FU)
            {
                return false;
            }
        }
        return true;
    }

    bool setCommonName(X509_NAME* subject, std::string_view common_name)
    {
        return X509_NAME_add_entry_by_NID(
                   subject,
                   NID_commonName,
                   MBSTRING_UTF8,
                   reinterpret_cast<const unsigned char*>(common_name.data()),
                   static_cast<int>(common_name.size()),
                   -1,
                   0) == 1;
    }

    bool setSerial(X509* certificate)
    {
        std::array<unsigned char, 16> random{};
        randombytes_buf(random.data(), random.size());
        random[0] &= 0x7FU;
        BigNumPtr number(BN_bin2bn(
                             random.data(),
                             static_cast<int>(random.size()),
                             nullptr),
                         BN_free);
        sodium_memzero(random.data(), random.size());
        if (!number)
        {
            return false;
        }
        Asn1IntegerPtr serial(BN_to_ASN1_INTEGER(number.get(), nullptr), ASN1_INTEGER_free);
        return serial && X509_set_serialNumber(certificate, serial.get()) == 1;
    }

    bool addExtension(
        X509* certificate,
        X509* issuer,
        int nid,
        const char* value)
    {
        X509V3_CTX context{};
        X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
        ExtensionPtr extension(
            X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value)),
            X509_EXTENSION_free);
        return extension &&
               X509_add_ext(certificate, extension.get(), -1) == 1;
    }

    bool addNameAndValidity(
        X509* certificate,
        std::string_view common_name,
        std::uint64_t validity_days)
    {
        if (!setSerial(certificate) ||
            X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == nullptr ||
            X509_gmtime_adj(
                X509_getm_notAfter(certificate),
                static_cast<long>(validity_days * 24U * 60U * 60U)) == nullptr)
        {
            return false;
        }

        X509_NAME* subject = X509_get_subject_name(certificate);
        return subject != nullptr && setCommonName(subject, common_name);
    }

    bool bioToString(BIO* bio, std::string& output)
    {
        BUF_MEM* memory = nullptr;
        BIO_get_mem_ptr(bio, &memory);
        if (memory == nullptr || memory->data == nullptr || memory->length == 0)
        {
            return false;
        }
        output.assign(memory->data, memory->length);
        return true;
    }
}

bool PkiEngine::supportsOperation(std::string_view operation) const noexcept
{
    return operation == "PKI_CREATE_CA" ||
           operation == "PKI_ISSUE_CERTIFICATE";
}

bool PkiEngine::createAuthority(
    std::string_view common_name,
    std::string& out_private_bundle,
    std::string& out_certificate) const
{
    if (!validCommonName(common_name) || sodium_init() < 0)
    {
        return false;
    }

    KeyContextPtr key_context(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                              EVP_PKEY_CTX_free);
    EVP_PKEY* raw_key = nullptr;
    if (!key_context ||
        EVP_PKEY_keygen_init(key_context.get()) <= 0 ||
        EVP_PKEY_keygen(key_context.get(), &raw_key) <= 0)
    {
        return false;
    }
    KeyPtr private_key(raw_key, EVP_PKEY_free);

    CertificatePtr certificate(X509_new(), X509_free);
    if (!certificate ||
        X509_set_version(certificate.get(), 2) != 1 ||
        X509_set_pubkey(certificate.get(), private_key.get()) != 1 ||
        !addNameAndValidity(certificate.get(), common_name, MAX_CA_VALIDITY_DAYS))
    {
        return false;
    }

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    if (subject == nullptr ||
        X509_set_issuer_name(certificate.get(), subject) != 1 ||
        !addExtension(
            certificate.get(),
            certificate.get(),
            NID_basic_constraints,
            "critical,CA:TRUE,pathlen:0") ||
        !addExtension(
            certificate.get(),
            certificate.get(),
            NID_key_usage,
            "critical,digitalSignature,keyCertSign,cRLSign") ||
        X509_sign(certificate.get(), private_key.get(), nullptr) <= 0)
    {
        return false;
    }

    BioPtr bundle_bio(BIO_new(BIO_s_mem()), BIO_free);
    BioPtr certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bundle_bio || !certificate_bio ||
        PEM_write_bio_PrivateKey(bundle_bio.get(), private_key.get(), nullptr,
                                 nullptr, 0, nullptr, nullptr) != 1 ||
        PEM_write_bio_X509(bundle_bio.get(), certificate.get()) != 1 ||
        PEM_write_bio_X509(certificate_bio.get(), certificate.get()) != 1)
    {
        return false;
    }

    std::string bundle;
    std::string cert_pem;
    if (!bioToString(bundle_bio.get(), bundle) ||
        !bioToString(certificate_bio.get(), cert_pem))
    {
        return false;
    }
    out_private_bundle = std::move(bundle);
    out_certificate = std::move(cert_pem);
    return true;
}

bool PkiEngine::issueCertificate(
    std::string_view private_bundle,
    std::string_view common_name,
    std::uint64_t validity_days,
    std::string& out_certificate) const
{
    if (private_bundle.empty() || private_bundle.size() > 1024U * 1024U ||
        !validCommonName(common_name) ||
        validity_days == 0 || validity_days > MAX_LEAF_VALIDITY_DAYS)
    {
        return false;
    }

    BioPtr bundle_bio(
        BIO_new_mem_buf(private_bundle.data(), static_cast<int>(private_bundle.size())),
        BIO_free);
    if (!bundle_bio)
    {
        return false;
    }
    KeyPtr ca_key(PEM_read_bio_PrivateKey(bundle_bio.get(), nullptr, nullptr, nullptr),
                  EVP_PKEY_free);
    CertificatePtr ca_certificate(
        PEM_read_bio_X509(bundle_bio.get(), nullptr, nullptr, nullptr),
        X509_free);
    if (!ca_key || !ca_certificate || X509_check_ca(ca_certificate.get()) <= 0 ||
        X509_check_private_key(ca_certificate.get(), ca_key.get()) != 1)
    {
        return false;
    }

    KeyContextPtr key_context(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                              EVP_PKEY_CTX_free);
    EVP_PKEY* raw_key = nullptr;
    if (!key_context ||
        EVP_PKEY_keygen_init(key_context.get()) <= 0 ||
        EVP_PKEY_keygen(key_context.get(), &raw_key) <= 0)
    {
        return false;
    }
    KeyPtr subject_key(raw_key, EVP_PKEY_free);

    CertificatePtr certificate(X509_new(), X509_free);
    if (!certificate ||
        X509_set_version(certificate.get(), 2) != 1 ||
        X509_set_pubkey(certificate.get(), subject_key.get()) != 1 ||
        !addNameAndValidity(certificate.get(), common_name, validity_days) ||
        X509_set_issuer_name(
            certificate.get(),
            X509_get_subject_name(ca_certificate.get())) != 1 ||
        !addExtension(
            certificate.get(),
            ca_certificate.get(),
            NID_basic_constraints,
            "critical,CA:FALSE") ||
        !addExtension(
            certificate.get(),
            ca_certificate.get(),
            NID_key_usage,
            "critical,digitalSignature") ||
        !addExtension(
            certificate.get(),
            ca_certificate.get(),
            NID_ext_key_usage,
            "serverAuth,clientAuth") ||
        X509_sign(certificate.get(), ca_key.get(), nullptr) <= 0)
    {
        return false;
    }

    BioPtr certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!certificate_bio ||
        PEM_write_bio_X509(certificate_bio.get(), certificate.get()) != 1)
    {
        return false;
    }
    return bioToString(certificate_bio.get(), out_certificate);
}
