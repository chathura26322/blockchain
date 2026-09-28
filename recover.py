import json, sys
from shamir import recover, bytes_to_share

data = json.load(open("shares.json"))
original = int(open("key_original.txt").read(), 16)

indexes = [int(i) for i in sys.argv[1:]]
shares = [bytes_to_share(bytes.fromhex(data["guardians"][i]["share"][2:]))
          for i in indexes]

result = recover(shares)
print(f"Using guardians {indexes}")
print("Recovered:", format(result, "x"))
print("MATCH!" if result == original else "NO MATCH (not enough shares)")
