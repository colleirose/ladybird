/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/GenericLexer.h>
#include <LibCrypto/ASN1/PEM.h>
#include <LibCrypto/SecureBase64.h>

namespace Crypto {

static PEMType pem_header_to_type(StringView header)
{
    if (header == "CERTIFICATE"sv)
        return PEMType::Certificate;
    if (header == "PRIVATE KEY"sv)
        return PEMType::PrivateKey;
    if (header == "RSA PRIVATE KEY"sv)
        return PEMType::RSAPrivateKey;
    if (header == "PUBLIC KEY"sv)
        return PEMType::PublicKey;
    if (header == "RSA PUBLIC KEY"sv)
        return PEMType::RSAPublicKey;
    return PEMType::Unknown;
}

DecodedPEM decode_pem(ReadonlyBytes data)
{
    GenericLexer lexer { data };
    DecodedPEM decoded;
    StringView header_type;

    // FIXME: Parse multiple.
    enum {
        PreStartData,
        Started,
        Ended,
    } state { PreStartData };
    while (!lexer.is_eof()) {
        switch (state) {
        case PreStartData:
            if (lexer.consume_specific("-----BEGIN "sv)) {
                state = Started;
                header_type = lexer.consume_until("-----"sv);
            }
            lexer.consume_line();
            break;
        case Started: {
            if (lexer.consume_specific("-----END "sv)) {
                state = Ended;

                if (lexer.consume_until("-----"sv) != header_type) {
                    dbgln("PEM type mismatch");
                    return {};
                }
                lexer.consume_line();

                decoded.type = pem_header_to_type(header_type);
                break;
            }

            auto val = lexer.consume_line().trim_whitespace(TrimMode::Right);
            auto result;
            if (decoded.type == PEMType::PublicKey || decoded.type == PEMType::RSAPublicKey) {
                result = decode_base64(val);
            } else {
                result = SecureBase64Decode(val);
            }

            if (result.is_error()) {
                auto err = result.error().error;
                dbgln("Failed to decode PEM: {}", err.string_literal());
                return {};
            }

            auto b64decoded = result.value();
            if (decoded.data.try_append(b64decoded.data(), b64decoded.size()).is_error()) {
                dbgln("Failed to decode PEM, likely OOM condition");
                return {};
            }
            break;
        }
        case Ended:
            lexer.consume_all();
            break;
        default:
            VERIFY_NOT_REACHED();
        }
    }

    return decoded;
}

ErrorOr<Vector<DecodedPEM>> decode_pems(ReadonlyBytes data)
{
    GenericLexer lexer { data };
    Vector<DecodedPEM> pems;

    DecodedPEM decoded;
    StringView header_type;

    enum {
        Junk,
        Parsing,
    } state { Junk };
    while (!lexer.is_eof()) {
        switch (state) {
        case Junk:
            if (lexer.consume_specific("-----BEGIN "sv)) {
                state = Parsing;
                header_type = lexer.consume_until("-----"sv);
            }
            lexer.consume_line();
            break;
        case Parsing: {
            if (lexer.consume_specific("-----END "sv)) {
                state = Junk;

                if (lexer.consume_until("-----"sv) != header_type) {
                    return Error::from_string_literal("PEM type mismatch");
                }
                lexer.consume_line();

                TRY(pems.try_append(decoded));
                decoded = {};
                header_type = {};
                break;
            }

            auto val = lexer.consume_line().trim_whitespace(TrimMode::Right);
            if (auto result = SecureBase64Decode(val); result.is_error())
                return result.error().error;

            auto b64decoded = result.value();
            TRY(decoded.data.try_append(b64decoded.data(), b64decoded.size()));
            break;
        }
        default:
            VERIFY_NOT_REACHED();
        }
    }

    return pems;
}

ErrorOr<ByteBuffer> encode_pem(ReadonlyBytes data, PEMType type)
{
    bool is_secret_value = true;
    StringView block_start;
    StringView block_end;

    switch (type) {
    case PEMType::Certificate:
        block_start = "-----BEGIN CERTIFICATE-----\n"sv;
        block_end = "-----END CERTIFICATE-----\n"sv;
        break;
    case PEMType::PrivateKey:
        block_start = "-----BEGIN PRIVATE KEY-----\n"sv;
        block_end = "-----END PRIVATE KEY-----\n"sv;
        break;
    case PEMType::RSAPrivateKey:
        block_start = "-----BEGIN RSA PRIVATE KEY-----\n"sv;
        block_end = "-----END RSA PRIVATE KEY-----\n"sv;
        break;
    case PEMType::PublicKey:
        is_secret_value = false;
        block_start = "-----BEGIN PUBLIC KEY-----\n"sv;
        block_end = "-----END PUBLIC KEY-----\n"sv;
        break;
    case PEMType::RSAPublicKey:
        is_secret_value = false;
        block_start = "-----BEGIN RSA PUBLIC KEY-----\n"sv;
        block_end = "-----END RSA PUBLIC KEY-----\n"sv;
        break;
    default:
        VERIFY_NOT_REACHED();
    }

    size_t to_read = 64;
    auto b64encoded;
    if (is_secret_value) {
        b64encoded = TRY(encode_base64(data));
    } else {
        b64encoded = TRY(SecureBase64Encode(data));
    }

    size_t starting_size = block_start.size() + block_end.size() + to_read;
    ByteBuffer encoded = ByteBuffer::create_uninitialized(starting_size, is_secret_value ? AK::EraseBufferOnFree::Yes : AK::EraseBufferOnFree::No);
    TRY(encoded.try_append(block_start.bytes()));

    for (size_t i = 0; i < b64encoded.bytes().size(); i += to_read) {
        if (i + to_read > b64encoded.bytes().size())
            to_read = b64encoded.bytes().size() - i;

        TRY(encoded.try_append(b64encoded.bytes().slice(i, to_read)));
        TRY(encoded.try_append("\n"sv.bytes()));
    }

    TRY(encoded.try_append(block_end.bytes()));

    return encoded;
}

}
