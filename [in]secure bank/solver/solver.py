"""Forge a valid transaction token without hashpumpy.

This implements SHA-256 length extension in pure Python to avoid the
PY_SSIZE_T_CLEAN runtime error that the C-extension build of hashpumpy hits
on newer Python versions.
"""

from binascii import hexlify, unhexlify
from hashlib import md5
import struct


# SHA-256 constants
K = [
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr(x: int, n: int) -> int:
	return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _pad(msg_len_bytes: int) -> bytes:
	pad_len = (64 - ((msg_len_bytes + 1 + 8) % 64)) % 64
	return b"\x80" + b"\x00" * pad_len + struct.pack(">Q", msg_len_bytes * 8)


def _compress(state, chunk: bytes):
	assert len(chunk) == 64
	w = list(struct.unpack(">16I", chunk)) + [0] * 48
	for i in range(16, 64):
		s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
		s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
		w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

	a, b, c, d, e, f, g, h = state
	for i in range(64):
		S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
		ch = (e & f) ^ (~e & g)
		temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
		S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
		maj = (a & b) ^ (a & c) ^ (b & c)
		temp2 = (S0 + maj) & 0xFFFFFFFF
		h, g, f, e, d, c, b, a = (
			g,
			f,
			e,
			(d + temp1) & 0xFFFFFFFF,
			c,
			b,
			a,
			(temp1 + temp2) & 0xFFFFFFFF,
		)

	return [
		(a + state[0]) & 0xFFFFFFFF,
		(b + state[1]) & 0xFFFFFFFF,
		(c + state[2]) & 0xFFFFFFFF,
		(d + state[3]) & 0xFFFFFFFF,
		(e + state[4]) & 0xFFFFFFFF,
		(f + state[5]) & 0xFFFFFFFF,
		(g + state[6]) & 0xFFFFFFFF,
		(h + state[7]) & 0xFFFFFFFF,
	]


def _process(state, data: bytes):
	assert len(data) % 64 == 0
	for i in range(0, len(data), 64):
		chunk = data[i : i + 64]
		state = _compress(state, chunk)
	return state


def sha256_lenext(orig_digest_hex: str, append: bytes, key_len: int, orig_data: bytes):
	state = [int(orig_digest_hex[i : i + 8], 16) for i in range(0, 64, 8)]

	ml = key_len + len(orig_data)  # bytes already hashed (secret + orig_data)
	pad1 = _pad(ml)

	total_len = ml + len(pad1) + len(append)
	pad2 = _pad(total_len)

	continuation = append + pad2
	state2 = _process(state, continuation)

	new_digest_hex = "".join(f"{x:08x}" for x in state2)
	forged_data = orig_data + pad1 + append
	return new_digest_hex, forged_data


user = "a"  # the name you entered at start
orig_token = input("Paste token from option 2: ").strip()

raw = unhexlify(orig_token)
parts = raw.split(b"|")
data, inner_hex, outer_hex = parts[-3], parts[-2], parts[-1]
orig_data = data
known_digest = inner_hex.decode()

suffix = b"|" + user.encode() + b"->bank:-10000000"
new_inner_hex, new_data = sha256_lenext(known_digest, suffix, 16, orig_data)
new_outer_hex = md5(new_inner_hex.encode()).hexdigest()
forged = hexlify(new_data + b"|" + new_inner_hex.encode() + b"|" + new_outer_hex.encode())
print(f"Forged token:\n{forged.decode()}")