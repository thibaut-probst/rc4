class RC4:
    """RC4 Class providing encryption and decryption capacities for a given secret key
    """
    
    def __init__(self, key):
        """Constructor
        Args:
            key (str): RC4 encryption and decryption key
        """
        self.key = key

    
    def ksa(self):
        """Key Scheduling Algorithm function that generates a permutation array from the key
        
        :Returns: a permutation array
        """
        key_b = [ord(c) for c in self.key] # convert string to byte
        key_length = len(key_b)
        S = list(range(256)) # initialize S
        j = 0
        for i in range(256):
            j = (j + S[i] + key_b[i % key_length]) % 256 # generate new pointer j from key
            S[i], S[j] = S[j], S[i]  # swap S[i] and S[j]
        return S   


    def prga(self, S, plaintext_length=0):
        """Pseudo Random Generation Algorithm selection function using either a generator (we'll iterate over what we'll need) or a list return (looping over the passed length of the plaintext)

        Args:
            S (list): permutation array
            plaintext_length (int, optional): length of the plaintext to encrypt. Defaults to 0.

        Returns:
            K (list or generator): keystream
        """        
        if plaintext_length != 0:
            return self.prga_return(S, plaintext_length)
        else:
            K = self.prga_generator(S)
            return K


    def prga_return(self, S, plaintext_length):
        """Pseudo Random Generation Algorithm based on a list return (looping over the passed length of the plaintext)

        Args:
            S (list): permutation array
            plaintext_length (int, optional): length of the plaintext to encrypt. Defaults to 0.

        Returns:
            K (list): keystream
        """        
        i = j = 0
        K = []
        for n in range(plaintext_length):
            i = (i + 1) % 256 # update pointer i
            j = (j + S[i]) % 256 # update pointer j
            S[i], S[j] = S[j], S[i] # swap S[i] and S[j]
            K.append(S[(S[i] + S[j]) % 256]) # generate random number K and append it to list
        return K # return a list


    def prga_generator(self, S):
        """Pseudo Random Generation Algorithm based on a generator (we'll iterate over what we'll need)

        Args:
            S (list): permutation array

        Returns:
            K (generator): keystream
        """  
        i = j = 0
        while True: # for as many operations needed
            i = (i + 1) % 256 # update pointer i
            j = (j + S[i]) % 256 # update pointer j
            S[i], S[j] = S[j], S[i] # swap S[i] and S[j]
            K = S[(S[i] + S[j]) % 256] # generate random number K
            yield K # return a generator   


    def xor_bytes(self, bytes1, bytes2):
        """XOR function between two byte arrays

        Args:
            bytes1 (list): first byte array
            bytes2 (list): second byte array

        Returns:
            list: resulting XOR byte array
        """        
        return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])


    def encrypt(self, plaintext, output_format='hex'):
        """RC4 encryption function

        Args:
            plaintext (str): plaintext to encrypt
            output_format (str, optional): output format of the returned ciphertext. Defaults to 'hex'.

        Returns:
            str: RC4 encrypted ciphertext in the given output format
        """
        plaintext_b = [ord(c) for c in plaintext] # convert string to byte
        keystream = self.prga(self.ksa()) # generate keystream
        keystream_list = []
        if not (type(keystream) is list):
            for i in range(len(plaintext_b)):
                keystream_list.append(next(keystream))
            keystream = keystream_list
        match output_format:
            case 'hex':
                return self.xor_bytes(plaintext_b, keystream).hex() # perform bytewise XOR and return in hex format
            case 'bin':
                return self.xor_bytes(plaintext_b, keystream) # perform bytewise XOR and return in bytes format
            case 'unicode':
                # perform bytewise XOR
                cipertext_b = self.xor_bytes(plaintext_b, keystream)
                cipertext_unicode = ''
                for b in cipertext_b:
                    cipertext_unicode += chr(b)
                return cipertext_unicode # return in unicode format
            case _: 
                return self.xor_bytes(plaintext_b, keystream).hex() # perform bytewise XOR and return in hex format


    def decrypt(self, ciphertext, output_format='unicode'):
        """RC4 decryption function

        Args:
            ciphertext (str): ciphertext to decrypt in hex format
            output_format (str, optional): output format of the returned plaintext. Defaults to 'unicode'.

        Returns:
            str: RC4 decrypted plaintext in the given output format
        """        
        keystream = self.prga(self.ksa()) # generate keystream
        ciphertext_b = bytes.fromhex(ciphertext) # convert hex to byte
        plaintext_b = self.xor_bytes(ciphertext_b, keystream) # perform bytewise XOR
        match output_format:
            case 'unicode':
                plaintext_unicode = ''
                for b in plaintext_b:
                    plaintext_unicode += chr(b)
                return plaintext_unicode # return in str format
            case _:
                return [chr(b) for b in self.xor_bytes(ciphertext_b, keystream)] # return in unicode format
