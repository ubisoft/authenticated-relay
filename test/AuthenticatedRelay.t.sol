// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {RelayData, AuthenticatedRelay} from "../src/AuthenticatedRelay.sol";

import {ERC721Items} from "@0xsequence/contracts-library/tokens/ERC721/presets/items/ERC721Items.sol";

contract AuthenticatedRelayTest is Test {
    uint256 internal constant OWNER_PRIVATE_KEY = 0x1;
    uint256 internal constant OPERATOR_PRIVATE_KEY = 0xFF;
    address internal owner;
    address internal operator;
    address internal recipient;
    AuthenticatedRelay internal relay;
    ERC721Items internal token;

    event SignatureUsed(bytes32 indexed hash, bool isRevoked);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function setUp() public {
        owner = vm.addr(OWNER_PRIVATE_KEY);
        operator = vm.addr(OPERATOR_PRIVATE_KEY);
        recipient = vm.addr(0x2);
        token = new ERC721Items();
        token.initialize(owner, "Test", "PFP", "ipfs://base/", "ipfs://contract/", owner, 5000);

        relay = new AuthenticatedRelay("AuthenticatedRelay", "1", owner, operator);
        vm.prank(owner);
        token.grantRole(keccak256("MINTER_ROLE"), address(relay));
    }

    function testRelay() public {
        bytes32 nonce = keccak256(abi.encode(recipient));
        uint256 amount = 5;
        bytes memory callData = abi.encodeWithSelector(ERC721Items.mint.selector, recipient, amount);
        RelayData memory data = RelayData({
            nonce: nonce,
            to: address(token),
            validityStart: block.timestamp,
            validityEnd: block.timestamp + 1 days,
            chainId: block.chainid,
            callData: callData
        });
        bytes32 digest = relay.hashTypedDataV4(data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PRIVATE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Expect SignatureUsed event
        vm.expectEmit();
        emit SignatureUsed(nonce, false);

        // Expect Transfer events
        vm.expectEmit();
        for (uint256 i = 0; i < amount; i++) {
            emit Transfer(address(0), recipient, i);
        }

        // Mint
        relay.relay(data, sig);

        // Check balance
        uint256 balance = token.balanceOf(recipient);
        assertEq(balance, amount);
    }

    function testRevoke() public {
        bytes32 nonce = keccak256(abi.encode(recipient));
        uint256 amount = 5;
        bytes memory callData = abi.encodeWithSelector(ERC721Items.mint.selector, recipient, amount);
        RelayData memory data = RelayData({
            nonce: nonce,
            to: address(token),
            validityStart: block.timestamp,
            validityEnd: 1 days,
            chainId: block.chainid,
            callData: callData
        });
        bytes32 digest = relay.hashTypedDataV4(data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PRIVATE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Expect SignatureUsed event
        vm.expectEmit();
        emit SignatureUsed(nonce, true);

        // Revoke nonce using OPERATOR private key
        vm.prank(vm.addr(OPERATOR_PRIVATE_KEY));
        relay.revoke(nonce);

        // Expect AlreadyUsed revert
        vm.expectRevert(AuthenticatedRelay.AlreadyUsed.selector);
        // Mint
        relay.relay(data, sig);

        // Check balance
        uint256 balance = token.balanceOf(recipient);
        assertEq(balance, 0);
    }
}
