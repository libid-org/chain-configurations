# Safe v1.4.1 runtime code

The runtime code of the four Safe v1.4.1 contracts `libid-deploy` creates
Safes through, as Ethereum holds it at their canonical addresses. Apply
installs it on a dev chain, which has no Safe deployment, and refuses it
unless it hashes to the code hash in `src/safes.rs`.

Regenerate a file from any Ethereum endpoint:

```sh
cast code 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67 --rpc-url <endpoint> > SafeProxyFactory.hex
cast code 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762 --rpc-url <endpoint> > SafeL2.hex
cast code 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99 --rpc-url <endpoint> > CompatibilityFallbackHandler.hex
cast code 0x9641d764fc13c8B624c04430C7356C1C7C8102e2 --rpc-url <endpoint> > MultiSendCallOnly.hex
```
