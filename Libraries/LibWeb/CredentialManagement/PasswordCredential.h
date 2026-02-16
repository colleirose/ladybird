/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibCore/SecretString.h>
#include <LibJS/Forward.h>
#include <LibWeb/Bindings/PasswordCredentialPrototype.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/CredentialManagement/Credential.h>
#include <LibWeb/CredentialManagement/CredentialUserData.h>
#include <LibWeb/HTML/HTMLFormElement.h>

namespace Web::CredentialManagement {

class PasswordCredential final
    : public Credential
    , public CredentialUserData {
    WEB_PLATFORM_OBJECT(PasswordCredential, Credential);
    GC_DECLARE_ALLOCATOR(PasswordCredential);

public:
    [[nodiscard]] static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, GC::Ptr<HTML::HTMLFormElement> const&);
    [[nodiscard]] static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, PasswordCredentialData const&);

    virtual ~PasswordCredential() override;

    Core::SecretString const& password() { return m_password; }
    URL::Origin const& origin() { return m_origin; }

    String type() override { return "password"_string; }

private:
    PasswordCredential(JS::Realm&, PasswordCredentialData const&, URL::Origin);
    virtual void initialize(JS::Realm&) override;

    // FIX-BEFORE-PR: needs more testing
    Core::SecretString m_password;

    // https://www.w3.org/TR/credential-management-1/#dom-credential-origin-slot
    URL::Origin m_origin;
};

struct PasswordCredentialData : CredentialData {
    Optional<String> name;
    Optional<String> icon_url;
    Core::SecretString password;
};

using PasswordCredentialInit = Variant<PasswordCredentialData, GC::Root<HTML::HTMLFormElement>>;

}
