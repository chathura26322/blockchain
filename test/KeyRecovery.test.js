const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("KeyRecovery", () => {
  let vault, owner, requester, g;

  beforeEach(async () => {
    const signers = await ethers.getSigners();
    owner = signers[0];
    requester = signers[1];
    g = signers.slice(2, 7); // 5 guardians
    const commitments = g.map((_, i) => ethers.id("share" + i));
    const F = await ethers.getContractFactory("KeyRecovery");
    vault = await F.deploy(g.map((s) => s.address), commitments, 3, 60);
  });

  it("recovers with 3 approvals after cooldown", async () => {
    await vault.connect(requester).initiateRecovery();
    for (let i = 0; i < 3; i++) await vault.connect(g[i]).approveRecovery();
    await time.increase(61);
    await expect(vault.connect(requester).finalizeRecovery())
      .to.emit(vault, "RecoveryFinalized");
  });

  it("fails with only 2 approvals", async () => {
    await vault.connect(requester).initiateRecovery();
    await vault.connect(g[0]).approveRecovery();
    await vault.connect(g[1]).approveRecovery();
    await time.increase(61);
    await expect(vault.connect(requester).finalizeRecovery())
      .to.be.revertedWith("not enough approvals");
  });

  it("fails before the cooldown ends", async () => {
    await vault.connect(requester).initiateRecovery();
    for (let i = 0; i < 3; i++) await vault.connect(g[i]).approveRecovery();
    await expect(vault.connect(requester).finalizeRecovery())
      .to.be.revertedWith("cooldown not over");
  });

  it("rejects double approval and non-guardians", async () => {
    await vault.connect(requester).initiateRecovery();
    await vault.connect(g[0]).approveRecovery();
    await expect(vault.connect(g[0]).approveRecovery())
      .to.be.revertedWith("already approved");
    await expect(vault.connect(requester).approveRecovery())
      .to.be.revertedWith("not a guardian");
  });

  it("lets the owner cancel", async () => {
    await vault.connect(requester).initiateRecovery();
    await vault.connect(owner).cancelRecovery();
    expect(await vault.recoveryActive()).to.equal(false);
  });
});
