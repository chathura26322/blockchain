// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Threshold key recovery coordinator
/// @notice Stores guardians + share commitments; enforces t-of-n approval
///         with a cooldown so the owner can cancel a malicious recovery.
contract KeyRecovery {
    address public owner;
    uint8 public threshold;
    uint256 public cooldown;              // seconds

    address[] public guardians;
    bytes32[] public commitments;         // sha256(share || salt)
    mapping(address => bool) public isGuardian;

    // Recovery state
    bool public recoveryActive;
    address public requester;
    uint256 public recoveryStart;
    uint256 public approvals;
    uint256 public round;                 // increments each recovery attempt
    mapping(uint256 => mapping(address => bool)) public approved;

    event RecoveryInitiated(uint256 indexed round, address indexed requester, uint256 readyAt);
    event Approved(uint256 indexed round, address indexed guardian, uint256 total);
    event RecoveryCancelled(uint256 indexed round);
    event RecoveryFinalized(uint256 indexed round, address indexed requester);
    event GuardianReplaced(uint256 indexed index, address oldG, address newG);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(
        address[] memory _guardians,
        bytes32[] memory _commitments,
        uint8 _threshold,
        uint256 _cooldown
    ) {
        require(_guardians.length == _commitments.length, "length mismatch");
        require(_threshold >= 2 && _threshold <= _guardians.length, "bad threshold");

        owner = msg.sender;
        threshold = _threshold;
        cooldown = _cooldown;

        for (uint256 i = 0; i < _guardians.length; i++) {
            address g = _guardians[i];
            require(g != address(0) && !isGuardian[g], "invalid guardian");
            isGuardian[g] = true;
            guardians.push(g);
            commitments.push(_commitments[i]);
        }
    }

    /// Anyone can start a recovery (the owner has lost their key, so it
    /// cannot be restricted to the owner).
    function initiateRecovery() external {
        require(!recoveryActive, "recovery already active");
        recoveryActive = true;
        requester = msg.sender;
        recoveryStart = block.timestamp;
        approvals = 0;
        round++;
        emit RecoveryInitiated(round, msg.sender, block.timestamp + cooldown);
    }

    function approveRecovery() external {
        require(recoveryActive, "no active recovery");
        require(isGuardian[msg.sender], "not a guardian");
        require(!approved[round][msg.sender], "already approved");
        approved[round][msg.sender] = true;
        approvals++;
        emit Approved(round, msg.sender, approvals);
    }

    /// Owner can stop a fake recovery during the cooldown window.
    function cancelRecovery() external onlyOwner {
        require(recoveryActive, "no active recovery");
        recoveryActive = false;
        emit RecoveryCancelled(round);
    }

    function finalizeRecovery() external {
        require(recoveryActive, "no active recovery");
        require(msg.sender == requester, "only requester");
        require(approvals >= threshold, "not enough approvals");
        require(block.timestamp >= recoveryStart + cooldown, "cooldown not over");
        recoveryActive = false;
        emit RecoveryFinalized(round, requester);
        // After this event, guardians release their shares to the requester
        // off-chain.
    }

    /// Check a share + salt against the stored commitment.
    function verifyShare(uint256 index, bytes calldata share, bytes32 salt)
        external view returns (bool)
    {
        return sha256(abi.encodePacked(share, salt)) == commitments[index];
    }

    /// Optional: owner swaps a guardian. See limitations in Section 8.
    function replaceGuardian(uint256 index, address newGuardian, bytes32 newCommitment)
        external onlyOwner
    {
        require(!recoveryActive, "recovery active");
        require(newGuardian != address(0) && !isGuardian[newGuardian], "invalid guardian");
        address old = guardians[index];
        isGuardian[old] = false;
        guardians[index] = newGuardian;
        isGuardian[newGuardian] = true;
        commitments[index] = newCommitment;
        emit GuardianReplaced(index, old, newGuardian);
    }

    function guardianCount() external view returns (uint256) {
        return guardians.length;
    }
}
