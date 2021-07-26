module CryptUtils

using Random: RandomDevice, randstring
using Nettle: hexdigest, gen_key32_iv16
using Primes: nextprime

export gen_salt, gen_key32, to_str, to_bytes, Bytes
export RSAKey, PublicRSAKey, PrivateRSAKey
export gen_RSAKeys, gen_prime, pack_int, unpack_int
export secure_rand, secure_randstring

const Bytes = Vector{UInt8}

abstract type RSAKey end

struct PublicRSAKey <: RSAKey
  e::BigInt
  n::BigInt
end

struct PrivateRSAKey <: RSAKey
  d::BigInt
  n::BigInt
end


"""
  secure_rand(start, stop)

Generates a relatively secure random number, based on the OS
"""
function secure_rand(start, stop)
  return rand(RandomDevice(), start:stop)
end

"""
  secure_randstring(len)

Generates a relatively secure random string, based on the OS
"""
function secure_randstring(len::Integer)::String
  return randstring(RandomDevice(), len)
end


"Packs an integer into an array of bytes"
function pack_int(num::Integer)::Bytes
  hex = string(num, base=16)
  pad = length(hex) % 2
  hex = ("0"^pad) * hex
  return hex2bytes(hex)
end

"Unpacks an array of bytes into a BigInt"
function unpack_int(b::Bytes)::BigInt
  hex = bytes2hex(b)
  return parse(BigInt, hex, base=16)
end

"""
  gen_prime(num_bits::Integer)::BigInt

Generates a random prime number with given number of bits
"""
function gen_prime(num_bits::Integer)::BigInt
  lower_bound = secure_rand(BigInt(2)^num_bits + 1, BigInt(2)^(num_bits+1))
  return nextprime(lower_bound)
end

"""
  gen_RSAKeys(num_bits::Integer = 2048)::Tuple{PublicRSAKey, PrivateRSAKey}

Generates Public and Private RSA Keys, given bit size of primes (default 2048)
"""
function gen_RSAKeys(num_bits::Integer = 2048)::Tuple{PublicRSAKey, PrivateRSAKey}
  size_offset = secure_rand(1, 5)

  # generate large primes p and q
  # make p and q differ by a few bits to make factoring harder
  p = gen_prime(num_bits)
  q = gen_prime(num_bits + size_offset) 

  n = p*q # RSAKey modulus
  λ_n = lcm(p - 1, q - 1) # Carmichael's totient function for n

  # compute e (public encryption key)
  e = secure_rand(2^16 + 1, λ_n)
  while gcd(e, λ_n) != 1
    e = secure_rand(1, λ_n)
  end

  # compute d (private decryption key)
  # such that d*e ≡ 1 mod λ_n
  d = invmod(e, λ_n)

  public_key = PublicRSAKey(e, n)
  private_key = PrivateRSAKey(d, n)

  return public_key, private_key
end

"Generates random 8-bit salt"
function gen_salt()::Bytes
  hex_val = hexdigest("sha256", secure_randstring(16))[1:16]
  return hex2bytes(hex_val)
end

"""
  gen_key([passphrase::String])

Generates 32 bit key, (can be influenced by a given passphrase, optional)
"""
function gen_key32()::Bytes
  passphrase = secure_randstring(16)
  salt = gen_salt()
  # generate key and initialization vector using passphrase and salt
  (key32, iv16) = gen_key32_iv16(Vector{UInt8}(passphrase), salt)
  return key32
end

function gen_key32(passphrase::String)::Bytes
  salt = gen_salt()
  # generate key and initialization vector using passphrase and salt
  (key32, iv16) = gen_key32_iv16(Vector{UInt8}(passphrase), salt)
  return key32
end

"Converts binary to ascii string"
function to_str(bytes::Bytes)::String
  return join(Char(i) for i in bytes)
end

"Converts ascii string to bytes (Vector{UInt8})"
function to_bytes(str::String)::Bytes
  return Bytes(str)
end

end # end of module

