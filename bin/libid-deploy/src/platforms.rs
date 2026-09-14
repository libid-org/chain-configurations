//! The launch platform table: what `IdentityNames.setPlatform` writes for
//! each keyspace.
//!
//! Nothing here is retyped. The platform domains and normalization rules
//! come from `libid-identity`'s generated table — the same one Solidity and
//! TypeScript read — and the profile shape from `libid-profiles`, generated
//! from `CeremonyProfile.sol`'s source. A value restated here would key
//! handles differently from every deployed reader.

use alloy::primitives::{
    keccak256,
    FixedBytes,
};
use libid_contracts::bindings::identity::IdentityNames;
use libid_identity::{
    handle_vectors as vectors,
    Rules,
};
use libid_profiles as profiles;

/// One launch platform.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Human label for logs and plan lines.
    pub label: &'static str,
    /// The platform's own bare name: libID namespaces only its own
    /// strings, and keccak256 of this is the on-chain platform id.
    pub domain: &'static str,
    /// The normalization rules `setPlatform` stores.
    pub rules: IdentityNames::Rules,
}

/// Widen a generated rule table into the contract's struct. `const` so a
/// value that does not fit the on-chain width fails the build below rather
/// than silently truncating into a keyspace nobody can resolve.
const fn on_chain_rules(rules: Rules) -> IdentityNames::Rules {
    IdentityNames::Rules {
        maxLength: rules.max_length as u16,
        stripLeadingAt: rules.strip_leading_at,
        isEmail: rules.is_email,
        allowUnderscore: rules.allow_underscore,
        allowHyphen: rules.allow_hyphen,
    }
}

/// X: letters, digits and underscore.
pub const X: Platform = Platform {
    label: "X",
    domain: vectors::PLATFORM_X_DOMAIN,
    rules: on_chain_rules(Rules::X),
};

/// GitHub: letters, digits and hyphen.
pub const GITHUB: Platform = Platform {
    label: "GitHub",
    domain: vectors::PLATFORM_GITHUB_DOMAIN,
    rules: on_chain_rules(Rules::GITHUB),
};

/// Google: an email address, used exactly as proved.
pub const GOOGLE: Platform = Platform {
    label: "Google",
    domain: vectors::PLATFORM_GOOGLE_DOMAIN,
    rules: on_chain_rules(Rules::GOOGLE),
};

/// The closed launch list, in deploy order. A platform outside it has no
/// profile, and the ceremony contracts revert on one.
pub const LAUNCH: &[Platform] = &[X, GITHUB, GOOGLE];

/// The launch platform with this domain, or nothing.
pub fn by_domain(domain: &str) -> Option<&'static Platform> {
    LAUNCH.iter().find(|p| p.domain == domain)
}

/// The on-chain platform id for a platform domain.
pub fn platform_id(domain: &str) -> FixedBytes<32> {
    keccak256(domain.as_bytes())
}

// The launch list is the profile table's launch list, and the generated
// widths fit the contract's. Checked where a mistake cannot run.
const _: () = {
    assert!(profiles::LAUNCH.len() == LAUNCH.len());
    assert!(Rules::X.max_length <= u16::MAX as usize);
    assert!(Rules::GITHUB.max_length <= u16::MAX as usize);
    assert!(Rules::GOOGLE.max_length <= u16::MAX as usize);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform ids come from the generated domains — a mistyped
    /// domain would key every handle differently from every deployed
    /// reader.
    #[test]
    fn platform_ids_come_from_the_generated_domains() {
        assert_eq!(platform_id(X.domain), keccak256(b"x"));
        assert_eq!(platform_id(GITHUB.domain), keccak256(b"github"));
        assert_eq!(platform_id(GOOGLE.domain), keccak256(b"google"));
        assert_ne!(platform_id(X.domain), platform_id(GITHUB.domain));
    }

    /// The rules written on chain are the generated ones, field for field.
    #[test]
    fn on_chain_rules_mirror_the_generated_table() {
        for (platform, rules) in [
            (X, Rules::X),
            (GITHUB, Rules::GITHUB),
            (GOOGLE, Rules::GOOGLE),
        ] {
            assert_eq!(platform.rules.maxLength as usize, rules.max_length);
            assert_eq!(platform.rules.stripLeadingAt, rules.strip_leading_at);
            assert_eq!(platform.rules.isEmail, rules.is_email);
            assert_eq!(platform.rules.allowUnderscore, rules.allow_underscore);
            assert_eq!(platform.rules.allowHyphen, rules.allow_hyphen);
        }
    }

    /// Every launch platform the profile table knows has a keyspace here.
    #[test]
    fn the_launch_list_matches_the_profile_table() {
        for profile in profiles::LAUNCH {
            assert!(
                by_domain(profile.platform).is_some(),
                "{} has a profile but no keyspace",
                profile.platform
            );
        }
        assert!(by_domain("discord").is_none());
    }
}
