// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.6;

import "./aBNBc_R3.sol";

contract EvilImplementation is aBNBc_R3 {
    function evilMint(address recipient, uint256 amount) external {
        _mint(recipient, amount);
    }
}
