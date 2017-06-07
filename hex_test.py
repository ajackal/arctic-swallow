import binascii

smb_header_negotiate = "\xff\x53\x4d\x42\x72"
# smb_header_negotiate = "0xff0x530x4d0x420x72"

file = 'pcaps/smb_response_win10'
with open(file, 'rb') as f:
    x = f.read()
    # z = binascii.hexlify(x)
    z = ""
    for i in x:
        r = binascii.hexlify(i)
        # r = hex(ord(i))
        z += "\\x" + r
        # z += r
    print z

# print type(smb_header_negotiate)
print type(z)

# if smb_header_negotiate in z:
#     print "SMB Header Found!"
# else:
#     print "Nothing found!"

# smb_found = z.find(smb_header_negotiate)
if z.find(smb_header_negotiate) is not 0:
    print "SMB Header found!"
else:
    print "Nothing found!"
