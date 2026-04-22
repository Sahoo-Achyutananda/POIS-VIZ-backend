from routes.pa5 import mac_route, MacRequest

print("Starting route test...")
req = MacRequest(mode="prf", key_hex="00112233445566778899aabbccddeeff", message_hex="68656c6c6f20776f726c64")
out = mac_route(req)
print(f"Success! {out}")
