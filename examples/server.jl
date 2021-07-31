include("../src/FluxFederated.jl")
using .FluxFederated
using Sockets
using Flux # Note: this takes awhile to load

# Listen on localhost port 3000
server = listen(3000)
con = accept(server)
println("Connected with a client")

# Establish shared AES key via RSA
shared_key = handshake_server(con)

# Communicate securely
secure_send(con, "Wanna train some models?", shared_key)
received_msg = secure_receive(con, shared_key) # --> "Oh yes"

println("Received: $received_msg")

# Create a Flux AI model
model = Chain(Dense(10,5,relu),Dense(5,2),softmax)

# Send model to client
model_bytes = model_to_bytes(model)
secure_send_bytes(con, model_bytes, shared_key)

println("Sent model: $model\n")

println("Model parameters:\n", params(model))

close(con)