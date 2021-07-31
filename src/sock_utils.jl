
using BSON: @save, @load
using Nettle
using Sockets

int(s::String) = parse(Int, s)
bigint(s::String) = parse(BigInt, s)

"""
  `var_to_bytes(variable)::Bytes`

Makes Byte representation (Vector{UInt8}) of given variable
This allows sending a variable over a socket connection in byte form
"""
function var_to_bytes(variable)::Bytes
  io = IOBuffer(write=true, read=true, append=true)
  write(io, variable)
  return read(io)
end

"""
  `model_to_bytes(model)::Bytes`

Converts a Flux model to Bytes (Vector{UInt8})
This allows sending a Flux model over a socket connection in byte form
""" 
function model_to_bytes(model)::Bytes
  io = IOBuffer(write=true, read=true, append=true)
  @save io model
  return read(io)
end

"""
  `var_from_bytes(bytes::Bytes, to_object)` -> variable

Writes byte data into already initialized object (to_object).
This allows sending a variable over a socket connection in byte form
"""
function var_from_bytes(bytes::Bytes, to_object)
  # write binary into buffer
  io = IOBuffer(read=true, write=true, append=true)
  write(io, bytes)

  # copy buffer data to object
  read!(io, to_object)
  return to_object
end

"""
  `model_from_bytes(bytes::Bytes)` -> Flux model
  
Loads a BSON model from Bytes
This allows receiving a Flux model over a socket connection in byte form
"""
function model_from_bytes(bytes::Bytes)
  #  write binary into buffer
  io = IOBuffer(read=true, write=true, append=true)
  write(io, bytes)

  # copy buffer data to object
  @load io model
  return model
end

"""
  `model_from_buffer(io::IOBuffer)` -> Flux model

Loads a BSON model from an IOBuffer (byte form)
This allows receiving a Flux model over a socket connection in byte form
"""
function model_from_buffer(io::IOBuffer)
  # copy buffer data to object
  seekstart(io)
  @load io model
  return model
end

"""
  `receive_multi_str(con::TCPSocket, start::String, stop::String)::String`

Receives multiple lines (as a String) from a TCP connection
Returns the string of everything between `start` and `stop`

`start`: prefix indicating start of desired message
`stop`: suffix indicating end of desired message
Both `start` and `stop` are removed from final resulting String
"""
function receive_multi_str(con::TCPSocket, start::String, stop::String)::String
  buf = IOBuffer(read=true, write=true, append=true)
  line = readline(con, keep=true)
  if !occursin(start, line)
    close(con)
    throw(ConnectionError("Server did not send expected start phrase: $start"))
  end
  line = split(line, start)[end]

  if occursin(stop, line)
    line = split(line, stop)[1]
    return line
  end

  while !occursin(stop, line)
    write(buf, line)
    line = readline(con, keep=true)
  end

  line = split(line, stop)[1]
  write(buf, line)
  content = read(buf)
  return to_str(content)
end


"""
  `send_int(con::TCPSocket, num::Integer)`

Sends integer to socket connection (First packs integer to bytes to reduce size)
"""
function send_int(con::TCPSocket, num::Integer)::Nothing
  num_bytes = pack_int(num)
  #  s = to_str(num_bytes) # <-- this becomes corrupted for large integers
  s = bytes2hex(num_bytes)
  prefix = "STARTINT"
  suffix = "STOPINT"
  res = write(con, prefix, s, suffix, "\n")
  if res != length(prefix) + length(s) + length(suffix) + 1 
    close(con)
    throw(ConnectionError("Failed to send integer ($res, $(length(s) + 16))"))
  end
end

"""
  `receive_int(con::TCPSocket)::BigInt`

Receive BigInt from socket connection (Assumes number was packed into bytes)
"""
function receive_int(con::TCPSocket)::BigInt
  try
    prefix = "STARTINT"
    suffix = "STOPINT"
    #  msg = readline(con, keep=true)
    msg = receive_multi_str(con, prefix, suffix)
    #  msg_bytes = to_bytes(strip(msg)) <-- this becomes corrupted for large integers
    msg_bytes = hex2bytes(strip(msg))
    num = unpack_int(msg_bytes)
    return num
  catch err
    close(con)
    throw(ConnectionError("Failed to receive valid integer"))
  end
end

"""
  `send_bytes(con::TCPSocket, msg::Bytes)::Nothing`

Sends Bytes over TCP socket connection
"""
function send_bytes(con::TCPSocket, msg::Bytes)::Nothing
  s = bytes2hex(msg)
  res = write(con, s, "\n")
  if res != length(s) + 1
    close(con)
    throw(ConnectionError("Failed to send bytes"))
  end
end


"""
  `receive_bytes(con::TCPSocket)::Bytes`

Receive Bytes (Vector{UInt8}) from TCP socket connection
"""
function receive_bytes(con::TCPSocket)::Bytes
  msg = readline(con, keep=false)
  try
    msg_bytes = hex2bytes(msg)
    return msg_bytes
  catch err
    close(con)
    throw(ConnectionError("Failed to receive bytes as expected"))
  end
end

"""
  `receive_str(con::TCPSocket)::String`

Receive String from socket connection
"""
function receive_str(con::TCPSocket)::String
  msg_bytes = receive_bytes(con)
  return to_str(msg_bytes)
end

"""
  `handshake_client(con::TCPSocket, [clientID::String])::Bytes` -> symmetric key

Establishes shared symmetric key (in Bytes) with server. Performs key exchange securely with RSA.
"""
function handshake_client(con::TCPSocket, clientID = nothing)::Bytes
  # Request passphase that server uses to initiate conversation
  expected_phrase = "INIT"
  phrase = readline(con, keep=true)
  if !occursin(expected_phrase, phrase)
    close(con)
    throw(ConnectionError("Expected handshake to start with phrase $expected_phrase"))
  end

  # Provide client ID to let server know client is authorized (optional)
  if typeof(clientID) != Nothing
    try
      write(con, "ID ", string(clientID), "\n")
    catch err
      throw(ArgumentError("clientID should be a String"))
    end
  else
    write(con, "NO_ID\n")
  end

  # Request server public key for RSA
  #  try
  #  catch err
    #  throw(ConnectionError("Server did not provide valid public key"))
  #  end
  pk_e = receive_int(con)
  pk_n = receive_int(con)
  public_key = PublicRSAKey(pk_e, pk_n)

  # Generate 32-bit symmetric key (in Bytes)
  symmetric_key = gen_key32()
  enc = Encryptor("AES256", symmetric_key)
  dec = Decryptor("AES256", symmetric_key)

  # Encrypt symmetric key with server's public key using RSA
  symmetric_key_int = unpack_int(symmetric_key)
  hidden_key = powermod(symmetric_key_int, public_key.e, public_key.n)

  # Send symmetric key to server (for AES)
  send_int(con, hidden_key)

  # Receive random message from server, encrypted with symmetric key
  ciphertext_bytes = receive_bytes(con)

  # Decrypt random message (using AES)
  msg_bytes = decrypt(dec, ciphertext_bytes)

  # Encrypt message with server's public key (using RSA)
  msg_int = unpack_int(msg_bytes)
  enc_msg = powermod(msg_int, public_key.e, public_key.n)

  # Send back encrypted message
  send_int(con, enc_msg)

  return symmetric_key
end

"""
  `handshake_server(con::TCPSocket, [verifyID])::Bytes` -> symmetric key

Establishes shared symmetric key (in Bytes) with client. Performs key exchange securely with RSA.

`verifyID`: a callback function, used to check if the client ID is authorized (optional)
"""
function handshake_server(con::TCPSocket, verifyID = nothing)
  # Send expected phrase to start handshake
  expected_phrase = "INIT"
  write(con, expected_phrase, "\n")

  # Obtain Client ID if available
  line = readline(con, keep=false)
  if !occursin("ID", line)
    close(con)
    throw(ConnectionError("Client did not provide client ID, or indicate that no ID is available"))
  end
  if !occursin("NO_ID", line)
    clientID = split("ID ", line)[2]
  else
    clientID = nothing
  end

  # Verify that client ID is authorized using callback function (optional)
  if typeof(verifyID) != Nothing
    verifyID(clientID)
  end

  # Generate RSA public key and private key
  public_key, private_key = gen_RSAKeys()

  # Send client public key for RSA
  send_int(con, public_key.e)
  send_int(con, public_key.n)

  # Receive encrypted symmetric key for AES
  hidden_key = receive_int(con)

  # Decrypt key using RSA, and decode to Bytes
  symmetric_key_int = powermod(hidden_key, private_key.d, private_key.n)
  symmetric_key = pack_int(symmetric_key_int) # Bytes

  # Generate random message (64 bits)
  random_message = secure_randstring(64)
  random_message_bytes = Bytes(random_message)

  # Encrypt message with AES and send to client
  enc = Encryptor("AES256", symmetric_key)
  encrypted_message = encrypt(enc, random_message_bytes)
  send_bytes(con, encrypted_message)

  # Receive message encrypted with RSA public key
  hidden_msg = receive_int(con)

  # Decrypt message using RSA, and decode to String
  msg_int = powermod(hidden_msg, private_key.d, private_key.n)
  msg_bytes = pack_int(msg_int)
  msg = to_str(msg_bytes)

  # Check if handshake was successful
  if msg != random_message
    close(con)
    throw(ConnectionError("Failed to establish shared symmetric key with client"))
  end

  return symmetric_key
end

"""
  `secure_send(con::TCPSocket, msg::String, AES_key::Bytes)::Nothing`

Encrypts message (String) with AES256 and sends it over socket connection
"""
function secure_send(con::TCPSocket, msg::String, AES_key::Bytes)::Nothing
  enc = Encryptor("AES256", AES_key)
  pad_length = (16 - (length(msg) % 16)) % 16
  padded_msg = ("\n"^pad_length) * msg
  padded_msgmsg = to_bytes(msg)
  enc_msg = encrypt(enc, padded_msg)
  send_bytes(con, enc_msg)
end

"""
  `secure_receive(con::TCPSocket, AES_key::Bytes)::String`

Receives and decrypts message (String) from TCP Socket connection using AES256
(Note that white space padding will get stripped from the ends of the message)
"""
function secure_receive(con::TCPSocket, AES_key::Bytes)::String
  dec = Decryptor("AES256", AES_key)
  enc_msg = receive_bytes(con)
  msg_bytes =  decrypt(dec, enc_msg)
  return strip(to_str(msg_bytes))
end

"""
  `secure_send_bytes(con::TCPSocket, msg::Bytes, AES_key::Bytes)::Nothing`

Encrypts message (Bytes / Vector{UInt8}) with AES256 and sends it over socket connection
"""
function secure_send_bytes(con::TCPSocket, msg::Bytes, AES_key::Bytes)::Nothing
  msg_hex = bytes2hex(msg)
  secure_send(con, msg_hex, AES_key)
end

"""
  `secure_receive_bytes(con::TCPSocket, AES_key::Bytes)::Bytes`

Receives and decrypts message (Bytes / Vector{UInt8}) from TCP Socket connection using AES256
(Note that white space padding will get stripped from the ends of the message)
"""
function secure_receive_bytes(con::TCPSocket, AES_key::Bytes)::Bytes
  msg = secure_receive(con, AES_key)
  return hex2bytes(msg)
end


"""
  `secure_send_int(con::TCPSocket, msg::Integer, AES_key::Bytes)::Nothing`

Encrypts message (BigInt) with AES256 and sends it over socket connection
"""
function secure_send_int(con::TCPSocket, msg::Integer, AES_key::Bytes)::Nothing
  msg_bytes = pack_int(msg)
  secure_send_bytes(con, msg_bytes, AES_key)
end

"""
  `secure_receive_int(con::TCPSocket, AES_key::Bytes)::BigInt`

Receives and decrypts message (BigInt) from TCP Socket connection using AES256
(Note that white space padding will get stripped from the ends of the message)
"""
function secure_receive_int(con::TCPSocket, AES_key::Bytes)::BigInt
  msg_bytes = secure_receive_bytes(con, AES_key)
  return unpack_int(msg_bytes)
end

