# FluxFederated

Keep your Flux models in style with Federated Learning


### TODO

```
[+] Send Flux model over TCP socket connection
[+] Support multiple connections, asynchronously
[+] Encrypt socket communication (RSA, AES)
[-] Pseudo-SecAgg (involves trusted 3rd party)
[-] FedAvg
[-] Local training commands
[-] Differential Privacy
[-] Federated Ensemble Support
[-] SecAgg (no trusted 3rd party)
```

##### ADDITIONAL FEATURES

```
[-] Adversarial Attacks
[-] Poisoning Attacks
[-] Reconstruction Attacks
```

### CURRENT USAGE

The following is an example of how an AI model can be securely sent over a single connection.

**Server**

```julia
include("SockUtils.jl")
using .SockUtils
using Sockets
using Flux

# Listen on localhost port 3000
server = listen(3000)
con = accept(server)

# Establish shared AES key via RSA
shared_key = handshake_server(con)

# Communicate securely
secure_send(con, "Wanna train some models?", shared_key)
secure_receive(con, shared_key) # --> "Oh yes"

# Create a Flux AI model
model = Chain(Dense(10,5,relu),Dense(5,2),softmax)

# Send model to client
model_bytes = model_to_bytes(model)
secure_send_bytes(con, model_bytes, shared_key)

```

**Client**
```julia
include("SockUtils.jl")
using .SockUtils
using Sockets
using Flux

# Connect to localhost port 3000
con = connect(3000)

# Establish shared AES key via RSA
shared_key = handshake_client(con)

# Communicate securely
secure_receive(con, shared_key) # --> "Wanna train some models?"
secure_send(con, "Oh yes", shared_key)

# Receive a Flux AI model via socket connection
model_bytes = secure_receive_bytes(con, shared_key)
model = model_from_bytes(model_bytes) # --> Chain(Dense(10,5,relu),Dense(5,2),softmax)
```
