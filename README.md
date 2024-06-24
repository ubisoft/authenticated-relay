# Authenticated relay

Solidity smart contract that verifies an authorisation signature before forwarding the call to the destination contract. Can be used for backend-gated minting.

## Overview

The relay is deployed on-chain and is configured with an `operator` role (`OPERATOR_ROLE`)
The backend signs an EIP-712 message of the following structure with an owner key:

```solidity
struct RelayData {
    bytes32 nonce;
    address to;
    uint256 validityStart;
    uint256 validityEnd;
    uint256 chainId;
    bytes callData;
}
```

Where `to` is the destination contract, `callData` is the ABI-encoded calldata. The relay verifies that the recovered signature matches an owner role and executes the call on the destination contract.

The `operator` address can be updated by the `admin` (`DEFAULT_ADMIN_ROLE`)

## Usage

This example uses a test agains [Sequence's ERC721 contract library](https://github.com/0xsequence/contracts-library/blob/master/src/tokens/ERC721/presets/items/ERC721Items.sol).
See `test/AuthenticatedRelay.t.sol` for details.

### Requirements
- Foundry: https://book.getfoundry.sh/

### Build
```shell
forge install
# build sequence contracts dependencies:
pushd lib/contracts-library
yarn && yarn build
popd

forge build
```

### Test
```shell
forge test
```