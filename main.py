import os
import zlib
import base64
from glob import glob
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def separator():
    print("-------------------------------------")


def menu():
    separator()
    print("1. Generate RSA private/public key")
    print("2. Image Encryption (1 image)")
    print("3. Image Decryption (1 image)")
    print("4. Image Encryption (directory)")
    print("5. Image Decryption (directory)")
    print("0. Exit Program")
    separator()


def generateKey():
    private_file = "private_key.pem"
    public_file = "public_key.pem"

    # Directory path
    input_path = input("Enter path to save key (Leave blank if use default): ")
    separator()

    if not input_path:
        # Current directory
        input_path = os.getcwd()

    # Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)

    # The private key in PEM format
    private_key = new_key.exportKey("PEM")

    # The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")

    fd = open(os.path.join(input_path, private_file), "wb")
    fd.write(private_key)
    fd.close()

    fd = open(os.path.join(input_path, public_file), "wb")
    fd.write(public_key)
    fd.close()

    print("Private Key: %s/%s" % (input_path, private_file))
    # print((private_key).decode("utf-8"))
    print("Public Key: %s/%s" % (input_path, public_file))
    # print((public_key).decode("utf-8"))
    separator()

    exit()

def encrypt_blob(blob, public_key):
    # Import the public key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    # Compress the data first
    blob = zlib.compress(blob)

    # In determining the chunk size, determine the private key length used in bytes
    # and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    # in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted = ("").encode("utf-8")

    while not end_loop:
        # The chunk
        chunk = blob[offset:offset + chunk_size]

        # If the data chunk is less then the chunk size, then we need to add
        # padding with " ". This indicates the we reached the end of the file
        # so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += (" ").encode("utf-8") * (chunk_size - len(chunk))

        # Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    # Base 64 encode the encrypted file
    return base64.b64encode(encrypted)

def encrypt_image():
    # Public key path
    public_key_input = input("Enter public key path (Leave blank if use default): ")
    separator()

    if not public_key_input:
        # Current directory
        public_key_input = os.path.join(os.getcwd(), "public_key.pem")
  
    # Use the public key for encryption
    fd = open(public_key_input, "rb")
    public_key = fd.read()
    fd.close()

    # Image path
    image_path = input("Enter image path to encrypt: ")
    separator()

    # Output directory path
    output_path = input("Enter encryption output directory path (Leave blank if use default): ")
    separator()

    if not output_path:
        # Current directory
        output_path = os.getcwd() + "/encrypted"

        # Check directory is exist
        if not os.path.exists(output_path):
            os.makedirs('encrypted')

    # Encrypting message
    original_name = os.path.basename(image_path)
    print("Image '%s' encrypting..." % (original_name))

    try:
        # Our candidate file to be encrypted
        fd = open(image_path, "rb")
        unencrypted_blob = fd.read()
        fd.close()

        encrypted_blob = encrypt_blob(unencrypted_blob, public_key)

        # Write the encrypted contents to a file
        fd = open(os.path.join(output_path, original_name + ".lock"), "wb")
        fd.write(encrypted_blob)
        fd.close()

        # Successfully encrypted message
        print("Image '%s' successfully encrypted." % (original_name))
    except:
        # Unsuccessfully encrypted message
        print("Image '%s' unsuccessfully encrypted." % (original_name))

    separator()
    exit()

def encrypt_all_image():
    # Public key path
    public_key_input = input("Enter public key path (Leave blank if use default): ")
    separator()

    if not public_key_input:
        # Current directory
        public_key_input = os.path.join(os.getcwd(), "public_key.pem")
  
    # Use the public key for encryption
    fd = open(public_key_input, "rb")
    public_key = fd.read()
    fd.close()

    # Directory path
    directory_path = input("Enter directory path to encrypt: ")
    separator()

    # Output directory path
    output_path = input("Enter encryption output directory path (Leave blank if use default): ")
    separator()

    if not output_path:
        # Current directory
        output_path = os.getcwd() + "/encrypted"

        # Check directory is exist
        if not os.path.exists(output_path):
            os.makedirs('encrypted')

    # Find image in directory
    image_extension = ["jpg", "png", "gif"]
    image_path_list = []

    for ext in image_extension:
        image_path_list.extend(glob('%s/*.%s' % (directory_path, ext)))

    # Encrypt all image
    for image_path in image_path_list:
        # Encrypting message
        original_name = os.path.basename(image_path)
        print("Image '%s' encrypting..." % (original_name))

        try:
            # Our candidate file to be encrypted
            fd = open(image_path, "rb")
            unencrypted_blob = fd.read()
            fd.close()

            encrypted_blob = encrypt_blob(unencrypted_blob, public_key)

            # Write the encrypted contents to a file
            fd = open(os.path.join(output_path, original_name + ".lock"), "wb")
            fd.write(encrypted_blob)
            fd.close()

            # Successfully encrypted message
            print("Image '%s' successfully encrypted." % (original_name))
        except:
            # Unsuccessfully encrypted message
            print("Image '%s' unsuccessfully encrypted." % (original_name))

    separator()
    exit()

def decrypt_blob(encrypted_blob, private_key):
    # Import the private key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    # Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    # In determining the chunk size, determine the private key length used in bytes.
    # The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = ("").encode("utf-8")

    # Keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        # The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        # Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    # Return the decompressed decrypted data
    return zlib.decompress(decrypted)

def decrypt_image():
    # Private key path
    private_key_input = input("Enter private key path (Leave blank if use default): ")
    separator()

    if not private_key_input:
        # Current directory
        private_key_input = os.path.join(os.getcwd(), "private_key.pem")

    # Use the private key for decryption
    fd = open(private_key_input, "rb")
    private_key = fd.read()
    fd.close()

    # Image path
    image_path = input("Enter image path to decrypt: ")
    separator()

    # Output directory path
    output_path = input("Enter decryption output directory path (Leave blank if use default): ")
    separator()

    if not output_path:
        # Current directory
        output_path = os.getcwd() + "/decrypted"

        # Check directory is exist
        if not os.path.exists(output_path):
            os.makedirs('decrypted')

    # Decrypting message
    original_name = os.path.basename(image_path)
    print("Image '%s' decrypting..." % (original_name))

    try:
        # Our candidate file to be decrypted
        fd = open(image_path, "rb")
        encrypted_blob = fd.read()
        fd.close()

        # Write the decrypted contents to a file
        fd = open(os.path.join(output_path, original_name.replace(".lock", "")), "wb")
        fd.write(decrypt_blob(encrypted_blob, private_key))
        fd.close()

        # Successfully decrypted message
        print("Image '%s' successfully decrypted." % (original_name))
    except:
        # Unsuccessfully decrypted message
        print("Image '%s' unsuccessfully decrypted." % (original_name))

    separator()
    exit()

def decrypt_all_image():
    # Private key path
    private_key_input = input("Enter private key path (Leave blank if use default): ")
    separator()

    if not private_key_input:
        # Current directory
        private_key_input = os.path.join(os.getcwd(), "private_key.pem")

    # Use the private key for decryption
    fd = open(private_key_input, "rb")
    private_key = fd.read()
    fd.close()

    # Directory path
    directory_path = input("Enter directory path to decrypt: ")
    separator()

    # Output directory path
    output_path = input("Enter decryption output directory path (Leave blank if use default): ")
    separator()

    if not output_path:
        # Current directory
        output_path = os.getcwd() + "/decrypted"

        # Check directory is exist
        if not os.path.exists(output_path):
            os.makedirs('decrypted')
    
    # Find image in directory
    image_extension = ["jpg", "png", "gif"]
    image_path_list = []
    image_path_list.extend(glob('%s/*.lock' % (directory_path)))
    
    # Decrypt all image
    for image_path in image_path_list:
        # Decrypting message
        original_name = os.path.basename(image_path)
        print("Image '%s' decrypting..." % (original_name))

        try:
            # Our candidate file to be decrypted
            fd = open(image_path, "rb")
            encrypted_blob = fd.read()
            fd.close()

            # Write the decrypted contents to a file
            fd = open(os.path.join(output_path, original_name.replace(".lock", "")), "wb")
            fd.write(decrypt_blob(encrypted_blob, private_key))
            fd.close()

            # Successfully decrypted message
            print("Image '%s' successfully decrypted." % (original_name))
        except:
            # Unsuccessfully decrypted message
            print("Image '%s' unsuccessfully decrypted." % (original_name))
    
    separator()
    exit()


def main():
    separator()
    print("ImageProtection by max180643")
    menu()
    option = int(input("Select an option [0-5]: "))
    separator()

    while option != 0:
        if option == 1:
            # Generate RSA private/public key
            generateKey()
        elif option == 2:
            # Encrypting image using the public key
            encrypt_image()
        elif option == 3:
            # Decrypting image using the private key
            decrypt_image()
        elif option == 4:
            # Encrypting all image in directory using the public key
            encrypt_all_image()
        elif option == 5:
            # Decrypting all image in directory using the private key
            decrypt_all_image()
        else:
            print("Invalid option.")
            menu()
            option = int(input("Select an option [0-5]: "))
            separator()

    exit()

main()
