// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {AccessControl} from "openzeppelin-v5/access/AccessControl.sol";
import {ECDSA} from "openzeppelin-v5/utils/cryptography/ECDSA.sol";
import {EIP712} from "openzeppelin-v5/utils/cryptography/EIP712.sol";

struct RelayData {
    bytes32 nonce;
    address to;
    uint256 validityStart;
    uint256 validityEnd;
    uint256 chainId;
    bytes callData;
}

contract AuthenticatedRelay is EIP712, AccessControl {
    bytes32 public constant RELAY_DATA_TYPEHASH = keccak256("RelayData(bytes32,address,uint256,uint256,uint256,bytes)");

    mapping(bytes32 => bool) public _usedNonces;

    event SignatureUsed(bytes32 indexed nonce);

    error AlreadyUsed();
    error InvalidSignature();
    error Unauthorized();
    error CallFailed();

    constructor(string memory _name, string memory _version, address owner) EIP712(_name, _version) {
        _grantRole(DEFAULT_ADMIN_ROLE, owner);
    }

    function relay(RelayData calldata data, bytes memory signature) external payable returns (bytes memory) {
        bytes32 _hash = _hashTypedDataV4(hashStruct(data));

        if (block.timestamp < data.validityStart || block.timestamp > data.validityEnd || block.chainid != data.chainId)
        {
            revert InvalidSignature();
        }

        address recovered = ECDSA.recover(_hash, signature);
        if (!hasRole(DEFAULT_ADMIN_ROLE, recovered)) {
            revert Unauthorized();
        }

        if (_usedNonces[data.nonce]) revert AlreadyUsed();
        _usedNonces[data.nonce] = true;

        emit SignatureUsed(data.nonce);

        (bool success, bytes memory result) = data.to.call{value: msg.value}(data.callData);
        if (!success) {
            revert CallFailed();
        }
        return result;
    }

    function revoke(bytes32 nonce) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_usedNonces[nonce]) revert AlreadyUsed();
        _usedNonces[nonce] = true;
        emit SignatureUsed(nonce);
    }

    function hashTypedDataV4(RelayData memory data) public view returns (bytes32) {
        return _hashTypedDataV4(hashStruct(data));
    }

    function hashStruct(RelayData memory data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(RELAY_DATA_TYPEHASH, data.nonce, data.to, data.validityStart, data.validityEnd, data.chainId, data.callData)
        );
    }
}
