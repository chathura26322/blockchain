import secrets, hashlib, json
from shamir import split, share_to_bytes

N, T = 5, 3

key = secrets.token_bytes(32)
shares = split(int.from_bytes(key, "big"), N, T)

guardians = []
for x, y in shares:
    share_bytes = share_to_bytes((x, y))
    salt = secrets.token_bytes(32)
    commitment = hashlib.sha256(share_bytes + salt).digest()
    guardians.append({
        "index": x - 1,                      # index used by the contract
        "share": "0x" + share_bytes.hex(),   # give privately to guardian
        "salt": "0x" + salt.hex(),           # give privately to guardian
        "commitment": "0x" + commitment.hex()  # goes on-chain
    })

with open("shares.json", "w") as f:
    json.dump({"guardians": guardians}, f, indent=2)

# For the demo only: saved so we can check recovery worked.
# In real life the owner would keep or destroy this.
with open("key_original.txt", "w") as f:
    f.write(key.hex())

print("Original key :", key.hex())
print("\nCommitments array for the contract constructor:")
print(json.dumps([g["commitment"] for g in guardians]))
