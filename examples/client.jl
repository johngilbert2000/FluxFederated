include("../src/FluxFederated.jl")
using .FluxFederated
using Sockets
using Flux # Note: this takes awhile to load

# Connect to localhost port 3000
con = connect(3000)
println("Connected to localhost port 3000")

# Establish shared AES key via RSA
shared_key = handshake_client(con)

# Communicate securely
received_msg = secure_receive(con, shared_key) # --> "Wanna train some models?"
secure_send(con, "Oh yes", shared_key)

println("Received: $received_msg")

# Receive a Flux AI model via socket connection
model_bytes = secure_receive_bytes(con, shared_key)
model = model_from_bytes(model_bytes) # --> Chain(Dense(10,5,relu),Dense(5,2),softmax)

println("Received model: $model\n")

println("Model parameters:\n", params(model))

close(con)