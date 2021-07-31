include("../src/FluxFederated.jl")
using .FluxFederated
using Sockets
using Flux # Note: this takes awhile to load

# Listen on localhost port 3000
server = listen(3000)

# Initialize model
model = Chain(Dense(10,5,relu),Dense(5,2),softmax)

println("Initial params\n", params(model), "\n")

# Serve model asynchronously
serve_model(server, model)
