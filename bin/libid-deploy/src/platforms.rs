//! The platform tables: what the Registry, the Bank and the IdentityNames
//! contract are configured with. Ported from the original monorepo's
//! deployers so a fresh deployment matches the running system exactly.

use alloy::primitives::{
    keccak256,
    FixedBytes,
};
use libid_contracts::bindings::identity::IdentityNames;

/// Registry resolve configs:
/// `(domain, endpoint, handlePrefix, idPrefix, idSuffix)`.
/// Mirrors the original monorepo's `PLATFORM_CONFIGS` (and the contracts'
/// `Deploy.s.sol`).
pub const PLATFORM_CONFIGS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "api.x.com",
        "/2/users/me",
        "\"username\":\"",
        "\"id\":\"",
        "\"",
    ),
    ("api.github.com", "/user", "\"login\":\"", "\"id\":", ","),
    ("discord.com", "/api/users/@me", "\"username\":\"", "", ""),
    (
        "www.googleapis.com",
        "/oauth2/v2/userinfo",
        "\"email\": \"",
        "",
        "",
    ),
];

/// Registry domains the X ZK and Google OIDC verifiers are wired under.
pub const X_DOMAIN: &str = "api.x.com";
/// See [`X_DOMAIN`].
pub const GOOGLE_DOMAIN: &str = "www.googleapis.com";

/// X's `/me`, as the notarized exchange reads. `platformName` is the SNI
/// the notary hashes into the attestation digests.
pub const X_ENDPOINT: &str = "/2/users/me";
/// See [`X_ENDPOINT`].
pub const X_HANDLE_PREFIX: &str = "\"username\":\"";
/// See [`X_ENDPOINT`].
pub const X_ID_PREFIX: &str = "\"id\":\"";
/// See [`X_ENDPOINT`].
pub const X_ID_SUFFIX: &str = "\"";

/// Bank web-prefix table, diffed on-chain before sending.
pub const WEB_PREFIXES: &[(&str, &str)] = &[
    ("api.github.com", "https://github.com/"),
    ("api.x.com", "https://x.com/"),
];

/// GitHub's `/user` response shape, as its JSON reads. The id is a bare
/// number ending at a comma, where X quotes its own.
pub const GITHUB_SHAPE: (&str, &str, &str, &str) =
    ("/user", "\"login\":\"", "\"id\":", ",");

/// One identity-names platform: the id domain, the observation-freshness
/// allowance, and the handle normalization rules the contract stores.
pub struct IdentityPlatform {
    /// Human label for logs.
    pub label: &'static str,
    /// keccak256 of this string is the on-chain platform id. These are the
    /// generated domains from `handles.json` — the historical prefix is
    /// load-bearing: every deployed reader keys on it.
    pub domain: &'static str,
    /// `maxFutureObservation` seconds.
    pub allowance: u64,
    /// The normalization rules, field for field from the generated table.
    pub rules: IdentityNames::Rules,
}

/// The proof version a platform's first verifier is installed under.
///
/// Mirrors `IdentityNames.INITIAL_VERSION`, which numbers from one because
/// zero is that contract's "no verifier" sentinel. The anvil test asserts the
/// two agree, so a change on the contract side cannot pass silently here.
pub const INITIAL_VERSION: u32 = 1;

/// X: letters, digits and underscore, notary wall-clock (5 min skew).
pub const IDENTITY_X: IdentityPlatform = IdentityPlatform {
    label: "X",
    domain: "dyaka.identity.platform.x",
    allowance: 300,
    rules: IdentityNames::Rules {
        maxLength: 15,
        stripLeadingAt: true,
        isEmail: false,
        allowUnderscore: true,
        allowHyphen: false,
    },
};

/// GitHub: letters, digits and hyphen, notary wall-clock (5 min skew).
pub const IDENTITY_GITHUB: IdentityPlatform = IdentityPlatform {
    label: "GitHub",
    domain: "dyaka.identity.platform.github",
    allowance: 300,
    rules: IdentityNames::Rules {
        maxLength: 39,
        stripLeadingAt: true,
        isEmail: false,
        allowUnderscore: false,
        allowHyphen: true,
    },
};

/// Google: an email address, used exactly as proved. The OIDC circuit
/// exposes no `iat`, so the observation is the token's `exp` — about an
/// hour ahead of the moment it describes, hence the larger allowance.
pub const IDENTITY_GOOGLE: IdentityPlatform = IdentityPlatform {
    label: "Google",
    domain: "dyaka.identity.platform.google",
    allowance: 7200,
    rules: IdentityNames::Rules {
        maxLength: 62,
        stripLeadingAt: false,
        isEmail: true,
        allowUnderscore: false,
        allowHyphen: false,
    },
};

/// The on-chain platform id for an identity domain.
pub fn identity_platform_id(domain: &str) -> FixedBytes<32> {
    keccak256(domain.as_bytes())
}

// Google's observation is dated ahead of the moment it describes; the
// notary platforms are never ahead. Checked where a mistake cannot run.
const _: () = {
    assert!(IDENTITY_GOOGLE.allowance > IDENTITY_X.allowance);
    assert!(IDENTITY_X.allowance == IDENTITY_GITHUB.allowance);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform ids come from the generated domains — a mistyped domain
    /// here would key every handle differently from every deployed reader.
    #[test]
    fn identity_platform_ids_match_the_generated_domains() {
        assert_eq!(
            identity_platform_id(IDENTITY_X.domain),
            keccak256(b"dyaka.identity.platform.x")
        );
        assert_ne!(
            identity_platform_id(IDENTITY_X.domain),
            identity_platform_id(IDENTITY_GITHUB.domain)
        );
    }
}
