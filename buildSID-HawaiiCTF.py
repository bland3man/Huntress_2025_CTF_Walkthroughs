def bytes_to_sid(byte_list):
    # Revision and sub-authority count
    revision = byte_list[0]
    sub_auth_count = byte_list[1]

    # Identifier Authority (6 bytes, big-endian)
    identifier_authority = 0
    for b in byte_list[2:8]:
        identifier_authority = (identifier_authority << 8) | b

    # Sub-authorities (4 bytes each, little-endian)
    sub_auths = []
    offset = 8
    for _ in range(sub_auth_count):
        chunk = byte_list[offset:offset+4]
        value = chunk[0] | (chunk[1]<<8) | (chunk[2]<<16) | (chunk[3]<<24)
        sub_auths.append(value)
        offset += 4

    # Format SID string
    sid_str = f"S-{revision}-{identifier_authority}"
    for sa in sub_auths:
        sid_str += f"-{sa}"
    return sid_str


# Example usage
byte_list = [
    1,5,0,0,0,0,0,5,21,0,0,0,18,239,154,226,242,155,126,245,147,116,180,120,244,1,0,0
]

print(bytes_to_sid(byte_list))