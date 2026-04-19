/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Memory.h>
#include <LibCore/SecretString.h>
#include <LibJS/Forward.h>
#include <LibWeb/Bindings/PasswordCredentialPrototype.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/CredentialManagement/Credential.h>
#include <LibWeb/CredentialManagement/CredentialUserData.h>
#include <LibWeb/HTML/HTMLFormElement.h>

namespace Web::CredentialManagement {

// https://www.w3.org/TR/credential-management-1/#passwordcredential
class PasswordCredential final
    : public Credential
    , public CredentialUserData {
    WEB_PLATFORM_OBJECT(PasswordCredential, Credential);
    GC_DECLARE_ALLOCATOR(PasswordCredential);

public:
    [[nodiscard]] static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, GC::Ref<HTML::HTMLFormElement>);
    [[nodiscard]] static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, PasswordCredentialData const&);

    virtual ~PasswordCredential() override;

    Core::SecretString const& password() const { return m_password; }
    URL::Origin const& origin() const { return m_origin; }

    String type() const override { return "password"_string; }

private:
    PasswordCredential(JS::Realm&, PasswordCredentialData const&, URL::Origin);
    virtual void initialize(JS::Realm&) override;

    Core::SecretString m_password;

    // https://www.w3.org/TR/credential-management-1/#dom-credential-origin-slot
    URL::Origin m_origin;
};

// https://www.w3.org/TR/credential-management-1/#dictdef-passwordcredentialdata
struct PasswordCredentialData : CredentialData {
    Optional<String> name;
    Optional<String> icon_url;
    Core::SecretString password;
};

// https://www.w3.org/TR/credential-management-1/#typedefdef-passwordcredentialinit
using PasswordCredentialInit = Variant<PasswordCredentialData, GC::Root<HTML::HTMLFormElement>>;

}
