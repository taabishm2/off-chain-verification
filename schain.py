from Crypto.PublicKey import RSA
from hashlib import sha512

MODULUS_SIZE = 1024

# Manufacturer's public key encryption key data
MANUFACTURER_KEY_PAIR = RSA.generate(bits=MODULUS_SIZE)
MANUFACTURER_PVT_KEY = MANUFACTURER_KEY_PAIR.d
MANUFACTURER_PUB_KEY = MANUFACTURER_KEY_PAIR.e
MANUFACTURER_MODULUS = MANUFACTURER_KEY_PAIR.n

# Smart Contract's public key encryption key data
CONTRACT_KEY_PAIR = RSA.generate(bits=MODULUS_SIZE)
CONTRACT_PVT_KEY = CONTRACT_KEY_PAIR.d
CONTRACT_PUB_KEY = CONTRACT_KEY_PAIR.e
CONTRACT_MODULUS = CONTRACT_KEY_PAIR.n


def rsa_decrypt(ciphertext, decrypt_exponent, modulus):
    plaintext = pow(ciphertext, decrypt_exponent, modulus)
    return int.to_bytes(plaintext, MODULUS_SIZE, byteorder='big')


def sign_with_rsa(plaintext, private_exponent, modulus):
    message_digest = int.from_bytes(sha512(plaintext).digest(), byteorder='big')
    return rsa_encrypt(message_digest, private_exponent, modulus)


def rsa_encrypt(plaintext, encrypt_exponent, modulus):
    message_signature = pow(plaintext, encrypt_exponent, modulus)
    return message_signature


def rsa_verify_signature(signature, message_to_verify, public_exponent, modulus):
    calculated_message_digest = get_int(sha512(message_to_verify).digest())
    digest_from_signature = pow(signature, public_exponent, modulus)
    return calculated_message_digest == digest_from_signature


def get_bytes(int_input):
    return int.to_bytes(int_input, MODULUS_SIZE, byteorder="big")


def get_int(byte_input):
    return int.from_bytes(byte_input, byteorder='big')


def manufacture_product():
    product_attributes = b'product_id:1342; brand:acme; product_name:sample; price:USD 120; expiration:02-10-1997'
    manufacturer_product_signature = sign_with_rsa(product_attributes, MANUFACTURER_PVT_KEY, MANUFACTURER_MODULUS)

    return product_attributes, manufacturer_product_signature


def save_details_to_contract(product_attributes, manufacturer_product_signature):
    assert rsa_verify_signature(manufacturer_product_signature, product_attributes, MANUFACTURER_PUB_KEY, MANUFACTURER_MODULUS)
    contract_product_signature = rsa_encrypt(manufacturer_product_signature, CONTRACT_PVT_KEY, CONTRACT_MODULUS)

    return contract_product_signature


def verify_contract_signature_and_tag_product(contract_product_signature, manufacturer_product_signature):
    assert rsa_decrypt(contract_product_signature, CONTRACT_PUB_KEY, CONTRACT_MODULUS) == get_bytes(
        manufacturer_product_signature)
    # Either add product attributes, signatures & manufacturer public key to a tag physically attached to the product OR
    # Transfer the attributes, signatures & manufacturer public key via P2P transfer


def verify_product_attributes(contract_product_signature, manufacturer_pub_key):
    product_attributes_to_check = b'product_id:1342; brand:acme; product_name:sample; price:USD 120; expiration:02-10-1997'
    calculated_manufacturer_signature = rsa_decrypt(contract_product_signature, CONTRACT_PUB_KEY, CONTRACT_MODULUS)

    assert rsa_verify_signature(get_int(calculated_manufacturer_signature), product_attributes_to_check,
                                manufacturer_pub_key, MANUFACTURER_MODULUS)
    print("Verified!")


def main():
    # 1. Manufacturer specifies product attributes and a manufacturer_product_signature on product manufacture
    product_attributes, manufacturer_product_signature = manufacture_product()

    # 2. Manufacturer requests upload of product details to the blockchain.
    # The contract verifies the manufacturer_product_signature and, if validated, generates a contract_product_signature
    contract_product_signature = save_details_to_contract(product_attributes, manufacturer_product_signature)

    # 3. Manufacturer validates the contract_product_signature.
    # If validated, the manufacturer passes on the product attributes, contract_product_signature and
    # manufacturer's public key to the next owner
    verify_contract_signature_and_tag_product(contract_product_signature, manufacturer_product_signature)

    # 4. An auditing party who wants to verify the product details must collect the contract_product_signature and
    # manufacturer product key from the previous owner.
    # Using this data, they can validate the details attached to the product
    verify_product_attributes(contract_product_signature, MANUFACTURER_PUB_KEY)


if __name__ == "__main__":
    main()
