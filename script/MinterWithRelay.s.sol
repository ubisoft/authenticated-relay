// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RelayData, AuthenticatedRelay} from "../src/AuthenticatedRelay.sol";

import {ERC721Items} from "@0xsequence/contracts-library/tokens/ERC721/presets/items/ERC721Items.sol";

contract MintWithRelay is Script {
    uint256 OPERATOR_PRIVATE_KEY = vm.envUint("OPERATOR_PRIVATE_KEY");
    address ERC721_CONTRACT = vm.envAddress("ERC721_CONTRACT");
    address RELAY_CONTRACT = vm.envAddress("RELAY_CONTRACT");
    address RECIPIENT = vm.envAddress("RECIPIENT");
    uint256 SENDER_PRIVATE_KEY = vm.envUint("SENDER_PRIVATE_KEY");
    uint256 NONCE = vm.envUint("NONCE");
    
    function run() public {

        ERC721Items token = ERC721Items(ERC721_CONTRACT);
        AuthenticatedRelay relay = AuthenticatedRelay(RELAY_CONTRACT);

        uint256 amount = 1;
        bytes memory callData = abi.encodeWithSelector(ERC721Items.mint.selector, RECIPIENT, amount);
        RelayData memory data = RelayData({
            nonce: keccak256(abi.encode(NONCE)),
            to: address(token),
            validityStart: block.timestamp,
            validityEnd: block.timestamp + 1 days,
            chainId: block.chainid,
            callData: callData
        });
        bytes32 digest = relay.hashTypedDataV4(data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PRIVATE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startBroadcast(vm.addr(SENDER_PRIVATE_KEY));
        relay.relay(data, sig);

    }
}
