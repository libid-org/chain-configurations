//! What the chain's answers mean for each plan line. Every type holds the
//! declared values and what the chain returned for one check, and becomes
//! the [`Item`] the plan prints; none of them reads the chain.

use alloy::primitives::{
    Address,
    B256,
    U256,
};
use libid_contracts::factory::CREATE2_DEPLOYER;

use super::{
    Item,
    Status,
};
use crate::{
    apply::Upgrade,
    circuits::Circuit,
    names::CanonicalContract,
    platforms::{
        Platform,
        LAUNCH_VERIFIER_VERSION,
    },
};

/// A chain read: its value, or the error text it failed with.
pub(crate) type Answer<T> = Result<T, String>;

/// Whether the chain holds code at a declared address. A code-less declared
/// address is a planned deploy: the address is deterministic, so apply
/// lands exactly there.
pub(crate) struct Code {
    /// The plan line, e.g. `contracts.identity_registry`.
    pub(crate) component: String,
    /// The declared address.
    pub(crate) address: Address,
    /// Whether the chain holds code there.
    pub(crate) present: bool,
}

impl From<Code> for Item {
    fn from(code: Code) -> Self {
        let address = code.address;
        if code.present {
            Item::new(code.component, Status::Ok, format!("{address:#x}"))
        } else {
            Item::new(
                code.component,
                Status::Deploy,
                format!(
                    "declared at {address:#x} — no code on-chain; apply would deploy it \
                     there"
                ),
            )
        }
    }
}

/// Whether the keyless CREATE2 deployer is installed.
pub(crate) struct Create2Deployer {
    /// Whether the chain holds code at its address.
    pub(crate) present: bool,
}

impl From<Create2Deployer> for Item {
    fn from(deployer: Create2Deployer) -> Self {
        if deployer.present {
            Item::new(
                "create2_deployer",
                Status::Ok,
                format!("{CREATE2_DEPLOYER:#x}"),
            )
        } else {
            Item::new(
                "create2_deployer",
                Status::Deploy,
                format!(
                    "{CREATE2_DEPLOYER:#x} has no code — apply would install it via the \
                     keyless presigned transaction"
                ),
            )
        }
    }
}

/// Whether the Notary Service trusts the declared notary signer.
pub(crate) struct NotarySigner {
    /// The declared `accounts.notary`.
    pub(crate) signer: Address,
    /// `isTrustedNotary(signer)`.
    pub(crate) trusted: Answer<bool>,
}

impl From<NotarySigner> for Item {
    fn from(check: NotarySigner) -> Self {
        let signer = check.signer;
        match check.trusted {
            Ok(true) => Item::new(
                "notary_service.signer",
                Status::Ok,
                format!("{signer:#x} is trusted"),
            ),
            Ok(false) => Item::new(
                "notary_service.signer",
                Status::Configure,
                format!(
                    "{signer:#x} is NOT trusted — apply would setNotary it. Untrusting \
                     the outgoing key is a separate governance call, so a rotation can \
                     overlap"
                ),
            ),
            Err(e) => Item::new(
                "notary_service.signer",
                Status::Warn,
                format!("isTrustedNotary read failed: {e}"),
            ),
        }
    }
}

/// Whether the Notary Service charges the declared fee.
pub(crate) struct NotaryFee {
    /// The declared `notary_service.fee_wei`.
    pub(crate) declared: U256,
    /// `fee()`.
    pub(crate) on_chain: Answer<U256>,
}

impl From<NotaryFee> for Item {
    fn from(check: NotaryFee) -> Self {
        let declared = check.declared;
        match check.on_chain {
            Ok(on_chain) if on_chain == declared => {
                Item::new("notary_service.fee", Status::Ok, format!("{declared} wei"))
            }
            Ok(on_chain) => Item::new(
                "notary_service.fee",
                Status::Configure,
                format!(
                    "{on_chain} wei on-chain, file says {declared} — apply sends setFee"
                ),
            ),
            Err(e) => Item::new(
                "notary_service.fee",
                Status::Warn,
                format!("fee read failed: {e}"),
            ),
        }
    }
}

/// Whether the identity registry dispatches through the declared Proof
/// Verifier; without that pointer `quoteBind` calls the zero address.
pub(crate) struct RegistryProofVerifier {
    /// The declared Proof Verifier.
    pub(crate) declared: Address,
    /// `proofVerifier()`.
    pub(crate) wired: Answer<Address>,
}

impl From<RegistryProofVerifier> for Item {
    fn from(check: RegistryProofVerifier) -> Self {
        let declared = check.declared;
        match check.wired {
            Ok(addr) if addr == declared => Item::new(
                "identity_registry.proof_verifier",
                Status::Ok,
                format!("{addr:#x}"),
            ),
            Ok(addr) => Item::new(
                "identity_registry.proof_verifier",
                Status::Configure,
                format!("points at {addr:#x}, file declares {declared:#x}"),
            ),
            Err(e) => Item::new(
                "identity_registry.proof_verifier",
                Status::Warn,
                format!(
                    "proofVerifier read failed: {e} — apply STOPS at this read unless \
                     it upgrades the implementation first (--upgrade identity-registry)"
                ),
            ),
        }
    }
}

/// Whether the registry accepts a platform's bindings: true once the Proof
/// Verifier routes the platform to a registered verifier.
pub(crate) struct AcceptsBindings {
    /// The platform.
    pub(crate) platform: &'static Platform,
    /// `acceptsBindings(platform id)`.
    pub(crate) accepts: Answer<bool>,
}

impl From<AcceptsBindings> for Item {
    fn from(check: AcceptsBindings) -> Self {
        let component = format!("identity_registry.accepts.{}", check.platform.key);
        match check.accepts {
            Ok(true) => Item::new(component, Status::Ok, "accepts bindings"),
            Ok(false) => Item::new(
                component,
                Status::Configure,
                "accepts no binding until apply registers the platform's verifier",
            ),
            Err(e) => Item::new(
                component,
                Status::Warn,
                format!("acceptsBindings read failed: {e}"),
            ),
        }
    }
}

/// Whether the escrow resolves through the declared identity registry. It
/// pays out to whoever that registry says holds a handle, and has no setter
/// to move it to another one.
pub(crate) struct EscrowRegistry {
    /// The declared identity registry.
    pub(crate) declared: Address,
    /// `registry()`.
    pub(crate) on_chain: Answer<Address>,
}

impl From<EscrowRegistry> for Item {
    fn from(check: EscrowRegistry) -> Self {
        let declared = check.declared;
        match check.on_chain {
            Ok(addr) if addr == declared => {
                Item::new("handle_escrow.registry", Status::Ok, format!("{addr:#x}"))
            }
            Ok(addr) => Item::new(
                "handle_escrow.registry",
                Status::Warn,
                format!(
                    "resolves through {addr:#x}, file declares {declared:#x} — apply \
                     stops here: only an escrow implementation that moves it, or a new \
                     canonical escrow name, changes this"
                ),
            ),
            Err(e) => Item::new(
                "handle_escrow.registry",
                Status::Warn,
                format!(
                    "registry read failed: {e} — apply STOPS at this read unless it \
                     upgrades the implementation first (--upgrade handle-escrow)"
                ),
            ),
        }
    }
}

/// Whether the root list pays the declared Notary Service for each
/// rotation.
pub(crate) struct RootsNotaryService {
    /// The declared Notary Service.
    pub(crate) declared: Address,
    /// `notaryService()`.
    pub(crate) on_chain: Answer<Address>,
}

impl From<RootsNotaryService> for Item {
    fn from(check: RootsNotaryService) -> Self {
        let declared = check.declared;
        match check.on_chain {
            Ok(addr) if addr == declared => Item::new(
                "google_jwt_roots.notary_service",
                Status::Ok,
                format!("{addr:#x}"),
            ),
            Ok(addr) => Item::new(
                "google_jwt_roots.notary_service",
                Status::Configure,
                format!("points at {addr:#x}, file declares {declared:#x}"),
            ),
            Err(e) => Item::new(
                "google_jwt_roots.notary_service",
                Status::Warn,
                format!("notaryService read failed: {e}"),
            ),
        }
    }
}

/// Whether the root list holds fresh keys; it holds nothing until a keeper
/// has landed a rotation.
pub(crate) struct RootsRotation {
    /// `needsRotation()`.
    pub(crate) needed: Answer<bool>,
}

impl From<RootsRotation> for Item {
    fn from(check: RootsRotation) -> Self {
        match check.needed {
            Ok(true) => Item::new(
                "google_jwt_roots.rotation",
                Status::Warn,
                "the trust list wants a rotation — every Google binding reverts \
                 UntrustedModulus until a keeper lands one. Not apply's job",
            ),
            Ok(false) => {
                Item::new("google_jwt_roots.rotation", Status::Ok, "trusted and fresh")
            }
            Err(e) => Item::new(
                "google_jwt_roots.rotation",
                Status::Warn,
                format!("needsRotation read failed: {e}"),
            ),
        }
    }
}

/// Whether a ceremony circuit's verifier sits at its factory address with
/// the vendored code.
pub(crate) struct CircuitVerifier {
    /// The circuit.
    pub(crate) circuit: Circuit,
    /// The CREATE3 name it deploys under.
    pub(crate) name: String,
    /// Where that name lands.
    pub(crate) address: Address,
    /// The code hash there, `None` when the address holds no code.
    pub(crate) codehash: Option<B256>,
    /// The code hash of the vendored verifier.
    pub(crate) vendored: B256,
}

impl From<CircuitVerifier> for Item {
    fn from(check: CircuitVerifier) -> Self {
        let CircuitVerifier {
            circuit,
            name,
            address,
            codehash,
            vendored,
        } = check;
        let component = format!("circuits.{}", circuit.name());
        match codehash {
            None => Item::new(
                component,
                Status::Deploy,
                format!(
                    "declared at {address:#x} — no code on-chain; apply would deploy \
                     '{name}' there"
                ),
            ),
            Some(hash) if hash == vendored => Item::new(
                component,
                Status::Ok,
                format!("{address:#x} (codehash {vendored:#x}, '{name}')"),
            ),
            Some(hash) => Item::new(
                component,
                Status::Warn,
                format!("{address:#x} holds codehash {hash:#x}, not the vendored {vendored:#x}"),
            ),
        }
    }
}

/// Whether a Platform Verifier's implementation pins the vendored circuit
/// verifier, and its trust roots point at the deployed one.
pub(crate) struct TrustRoots {
    /// The platform.
    pub(crate) platform: &'static Platform,
    /// Where its circuit's verifier is, or would be, deployed.
    pub(crate) circuit_address: Address,
    /// The code hash of the vendored circuit verifier.
    pub(crate) vendored: B256,
    /// `honkVerifier()`.
    pub(crate) wired: Answer<Address>,
    /// `circuitCodehash()`.
    pub(crate) pinned: Answer<B256>,
}

impl From<TrustRoots> for Item {
    fn from(check: TrustRoots) -> Self {
        let TrustRoots {
            platform,
            circuit_address,
            vendored,
            wired,
            pinned,
        } = check;
        let component = format!("{}.trust_roots", platform.component());
        let circuit = platform.circuit().name();
        match (wired, pinned) {
            (Ok(_), Ok(hash)) if hash != vendored => Item::new(
                component,
                Status::Warn,
                format!(
                    "the implementation pins circuit codehash {hash:#x}, the vendored \
                     {circuit} verifier is {vendored:#x} — apply needs --upgrade {}",
                    Upgrade::from(platform.verifier)
                ),
            ),
            (Ok(addr), Ok(_)) if addr == circuit_address => {
                Item::new(component, Status::Ok, format!("pins {addr:#x} ({circuit})"))
            }
            (Ok(addr), Ok(_)) => Item::new(
                component,
                Status::Configure,
                format!(
                    "pins {addr:#x}, the {circuit} verifier is {circuit_address:#x} — \
                     apply sends setTrustRoots"
                ),
            ),
            _ => Item::new(component, Status::Warn, "trust-root read failed"),
        }
    }
}

/// Whether a Platform Verifier is registered in the Supported Version Set.
pub(crate) struct Registration {
    /// The platform.
    pub(crate) platform: &'static Platform,
    /// Its declared Platform Verifier proxy.
    pub(crate) proxy: Address,
    /// `verifierOf(platform id, launch version)`, `None` while the Proof
    /// Verifier has no code.
    pub(crate) registered: Option<Answer<Address>>,
}

impl From<Registration> for Item {
    fn from(check: Registration) -> Self {
        let component = format!("ceremony.{}.registration", check.platform.key);
        let proxy = check.proxy;
        match check.registered {
            None => Item::new(
                component,
                Status::Deploy,
                "the Proof Verifier does not exist yet",
            ),
            Some(Ok(addr)) if addr == proxy => Item::new(
                component,
                Status::Ok,
                format!("v{LAUNCH_VERIFIER_VERSION} -> {addr:#x}"),
            ),
            Some(Ok(addr)) if addr == Address::ZERO => Item::new(
                component,
                Status::Configure,
                format!(
                    "nothing registered for v{LAUNCH_VERIFIER_VERSION} — apply sends \
                     setVerifier({proxy:#x})"
                ),
            ),
            Some(Ok(addr)) => Item::new(
                component,
                Status::Configure,
                format!(
                    "v{LAUNCH_VERIFIER_VERSION} points at {addr:#x}, file declares \
                     {proxy:#x}"
                ),
            ),
            Some(Err(e)) => Item::new(
                component,
                Status::Warn,
                format!("verifierOf read failed: {e}"),
            ),
        }
    }
}

/// Whether the factory's own `deployedAt` record agrees with the declared
/// address. A record that disagrees means the chain and the file describe
/// different deployments.
pub(crate) struct FactoryRecord {
    /// The canonical contract.
    pub(crate) contract: CanonicalContract,
    /// Its declared address.
    pub(crate) declared: Address,
    /// `deployedAt(name)`.
    pub(crate) recorded: Answer<Address>,
}

impl From<FactoryRecord> for Item {
    fn from(check: FactoryRecord) -> Self {
        let CanonicalContract { key, name } = check.contract;
        let declared = check.declared;
        let component = format!("factory.record.{key}");
        match check.recorded {
            Ok(addr) if addr == Address::ZERO => Item::new(
                component,
                Status::Skipped,
                format!("'{name}' not yet deployed by the factory"),
            ),
            Ok(addr) if addr == declared => {
                Item::new(component, Status::Ok, format!("'{name}' -> {addr:#x}"))
            }
            Ok(addr) => Item::new(
                component,
                Status::Warn,
                format!(
                    "factory recorded '{name}' at {addr:#x} but the file declares \
                     {declared:#x} — the deterministic invariant is broken"
                ),
            ),
            Err(e) => Item::new(
                component,
                Status::Warn,
                format!("deployedAt('{name}') read failed: {e}"),
            ),
        }
    }
}

/// Whether the factory is owned by the declared operational owner.
pub(crate) struct FactoryOwner {
    /// The declared `accounts.owner`; `None` keeps whoever owns it.
    pub(crate) declared: Option<Address>,
    /// `owner()`.
    pub(crate) owner: Answer<Address>,
}

impl From<FactoryOwner> for Item {
    fn from(check: FactoryOwner) -> Self {
        match (check.owner, check.declared) {
            (Ok(owner), Some(want)) if want != owner => Item::new(
                "factory.owner",
                Status::Configure,
                format!("{owner:#x} on-chain, accounts.owner declares {want:#x}"),
            ),
            (Ok(owner), _) => {
                Item::new("factory.owner", Status::Ok, format!("{owner:#x}"))
            }
            (Err(e), _) => Item::new(
                "factory.owner",
                Status::Warn,
                format!("owner read failed: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::{
        GOOGLE,
        X,
    };

    const DECLARED: Address = Address::repeat_byte(0x11);
    const OTHER: Address = Address::repeat_byte(0x22);

    /// A declared address with no code is a deploy at exactly that address.
    #[test]
    fn a_codeless_declared_address_is_a_deploy() {
        let item = Item::from(Code {
            component: "contracts.handle_escrow".into(),
            address: DECLARED,
            present: false,
        });
        assert_eq!(item.status, Status::Deploy);
        assert!(
            item.detail.contains(&format!("{DECLARED:#x}")),
            "{}",
            item.detail
        );
    }

    /// A fee that differs from the file is configured, naming both values.
    #[test]
    fn a_drifted_fee_is_configured() {
        let item = Item::from(NotaryFee {
            declared: U256::from(1000),
            on_chain: Ok(U256::from(7)),
        });
        assert_eq!(item.status, Status::Configure);
        assert_eq!(
            item.detail,
            "7 wei on-chain, file says 1000 — apply sends setFee"
        );
    }

    /// An escrow bound to another registry is a warning: apply cannot
    /// rebind it.
    #[test]
    fn an_escrow_on_another_registry_warns() {
        let item = Item::from(EscrowRegistry {
            declared: DECLARED,
            on_chain: Ok(OTHER),
        });
        assert_eq!(item.status, Status::Warn);
    }

    /// A pinned code hash other than the vendored one asks for the
    /// upgrade, even when the trust roots point at the right address.
    #[test]
    fn a_stale_pinned_codehash_asks_for_the_upgrade() {
        let item = Item::from(TrustRoots {
            platform: &X,
            circuit_address: DECLARED,
            vendored: B256::repeat_byte(0xaa),
            wired: Ok(DECLARED),
            pinned: Ok(B256::repeat_byte(0xbb)),
        });
        assert_eq!(item.component, "contracts.x_platform_verifier.trust_roots");
        assert_eq!(item.status, Status::Warn);
        assert!(
            item.detail.ends_with("--upgrade x-platform-verifier"),
            "{}",
            item.detail
        );
    }

    /// Trust roots on another verifier are configured by `setTrustRoots`.
    #[test]
    fn trust_roots_on_another_verifier_are_configured() {
        let vendored = B256::repeat_byte(0xaa);
        let item = Item::from(TrustRoots {
            platform: &GOOGLE,
            circuit_address: DECLARED,
            vendored,
            wired: Ok(OTHER),
            pinned: Ok(vendored),
        });
        assert_eq!(item.status, Status::Configure);
    }

    /// Without a Proof Verifier the registration is part of the deploy.
    #[test]
    fn no_proof_verifier_means_the_registration_deploys() {
        let item = Item::from(Registration {
            platform: &X,
            proxy: DECLARED,
            registered: None,
        });
        assert_eq!(item.component, "ceremony.x.registration");
        assert_eq!(item.status, Status::Deploy);
    }

    /// An empty registration slot is configured by `setVerifier`.
    #[test]
    fn an_empty_registration_slot_is_configured() {
        let item = Item::from(Registration {
            platform: &X,
            proxy: DECLARED,
            registered: Some(Ok(Address::ZERO)),
        });
        assert_eq!(item.status, Status::Configure);
        assert!(item.detail.contains("setVerifier"), "{}", item.detail);
    }

    /// A circuit verifier with foreign code is a warning, not a deploy.
    #[test]
    fn a_circuit_verifier_with_foreign_code_warns() {
        let item = Item::from(CircuitVerifier {
            circuit: X.circuit(),
            name: "libid.circuits.test".into(),
            address: DECLARED,
            codehash: Some(B256::repeat_byte(0xbb)),
            vendored: B256::repeat_byte(0xaa),
        });
        assert_eq!(item.status, Status::Warn);
    }

    /// A factory record the factory has not written yet is skipped.
    #[test]
    fn an_unwritten_factory_record_is_skipped() {
        let item = Item::from(FactoryRecord {
            contract: CanonicalContract {
                key: "handle_escrow",
                name: "libid.HandleEscrow",
            },
            declared: DECLARED,
            recorded: Ok(Address::ZERO),
        });
        assert_eq!(item.status, Status::Skipped);
    }

    /// A factory owned by someone other than the declared owner is
    /// configured; with no declared owner any owner is fine.
    #[test]
    fn the_factory_owner_converges_only_onto_a_declared_owner() {
        let drifted = Item::from(FactoryOwner {
            declared: Some(DECLARED),
            owner: Ok(OTHER),
        });
        assert_eq!(drifted.status, Status::Configure);
        let undeclared = Item::from(FactoryOwner {
            declared: None,
            owner: Ok(OTHER),
        });
        assert_eq!(undeclared.status, Status::Ok);
    }
}
