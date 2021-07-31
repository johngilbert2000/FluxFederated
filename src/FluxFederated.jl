module FluxFederated

# exceptions
include("exceptions.jl")
export ConnectionError

# crypt_utils
include("crypt_utils.jl")

export gen_salt, gen_key32, to_str, to_bytes, Bytes
export RSAKey, PublicRSAKey, PrivateRSAKey
export gen_RSAKeys, gen_prime, pack_int, unpack_int
export secure_rand, secure_randstring

# sock_utils
include("sock_utils.jl")

export handshake_client, handshake_server, secure_send, secure_receive
export secure_send_bytes, secure_send_int, secure_receive_bytes, secure_receive_int
export var_to_bytes, var_from_bytes, model_to_bytes, model_from_buffer, model_from_bytes

# serve
include("async_serve.jl")
export serve_model

end # module
