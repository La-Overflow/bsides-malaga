
import struct

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def getByte(number, n):
	return (number >> (8*n)) & 0xff


def main():
	size = 0 #should be 0xFE3
	decryption_key = 0 # should be 0x4A1AD4A1
	payload = []

	with open("encrypted_full.bin", "rb") as f:
		f.read(4) # first 4 bytes are just 0x0
		size = struct.unpack('<I', f.read(4))[0]
		decryption_key = struct.unpack('<I', f.read(4))[0]
		print("Size: {}\nKey: {}".format(hex(size), hex(decryption_key)))
		f.read(4) # 0x0
		payload = f.read()

	payload = bytearray(payload)

	edi = 0
	esi = 0
	i = size / 16 # 16 bytes decrypted in each iteration
	while i > 0:
		ah = payload[edi+6]
		al = payload[esi]
		payload[edi+6] = al ^ getByte(decryption_key, 0)
		payload[esi] = ah ^ getByte(decryption_key, 0)


		ah = payload[edi+0xC]
		al = payload[esi+1]
		payload[edi+0xC] = al ^ getByte(decryption_key, 1)
		payload[esi+1] = ah ^ getByte(decryption_key, 1)

		decryption_key = rol(decryption_key, 1, 32) # modify key

		ah = payload[edi+0xB]
		al = payload[esi+2]
		payload[edi+0xB] = al ^ getByte(decryption_key, 0)
		payload[esi+2] = ah ^ getByte(decryption_key, 0)

		ah = payload[edi+8]
		al = payload[esi+3]
		payload[edi+8] = al ^ getByte(decryption_key, 1)
		payload[esi+3] = ah ^ getByte(decryption_key, 1)

		decryption_key = ror(decryption_key, 1, 32) # modify key

		ah = payload[edi+9]
		al = payload[esi+4]
		payload[edi+9] = al ^ getByte(decryption_key, 0)
		payload[esi+4] = ah ^ getByte(decryption_key, 0)

		ah = payload[edi+0xF]
		al = payload[esi+5]
		payload[edi+0xF] = al ^ getByte(decryption_key, 1)
		payload[esi+5] = ah ^ getByte(decryption_key, 1)

		ah = payload[edi+0x0D]
		al = payload[esi+7]
		payload[edi+0x0D] = al ^ getByte(decryption_key, 0)
		payload[esi+7] = ah ^ getByte(decryption_key, 0)

		ah = payload[edi+0xE]
		al = payload[esi+0xA]
		payload[edi+0xE] = al ^ getByte(decryption_key, 1)
		payload[esi+0xA] = ah ^ getByte(decryption_key, 1)

		decryption_key = ror(decryption_key, 3, 32) # modify key

		edi += 0x10
		esi += 0x10
		i -= 1

	with open("decrypted.bin", "wb") as f:
		f.write(payload)

	print("Decrypted! :D")

main()
