include("../src/FluxFederated.jl")
using .FluxFederated
using Sockets
using Flux # Note: this takes awhile to load

"Adds a small number to model parameters"
function fake_update(model)
  W, restructure = Flux.destructure(model)
  num = 0.01 * rand()
  return restructure(W .+ Float32(num))
end

# Connect to localhost port 3000
con = connect(3000)
println("Connected to localhost port 3000")

# Establish shared AES key via RSA
shared_key = handshake_client(con)

# Receive a Flux AI model via socket connection
model_bytes = secure_receive_bytes(con, shared_key)
model = model_from_bytes(model_bytes) # --> Chain(Dense(10,5,relu),Dense(5,2),softmax)

# Update model
# ...
# TODO: Perform training here
model = fake_update(model)

# Send back updated model
model_bytes = model_to_bytes(model)
secure_send_bytes(con, model_bytes, shared_key)

println("Received model: $model\n")

println("Model parameters:\n", params(model))

close(con)