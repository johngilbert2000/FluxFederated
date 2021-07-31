
# FluxFederated

<img width="200px" src="https://github.com/johngilbert2000/FluxFederated/blob/main/misc/fed_logo.png" />

Make your [Flux](https://fluxml.ai/) models stylish with [Federated Learning](https://ai.googleblog.com/2017/04/federated-learning-collaborative.html).

Maybe protect some privacy too.

___

### EXAMPLES

The following is an example of how an AI model can be securely sent over a single connection.

**Server**

```julia
include("src/FluxFederated.jl")
using .FluxFederated
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
include("src/FluxFederated.jl")
using .FluxFederated
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

To see an example of federated averaging with multiple clients (i.e., multiple simultaneous connections), check out `async_server.jl` and `async_client.jl` in the `examples/` folder.

___

### TODO

- [X] Send Flux model over TCP socket connection
- [X] Encrypt socket communication (RSA, AES)
- [X] Support multiple connections, asynchronously
- [X] FedAvg
- [ ] Pseudo-SecAgg (involves trusted 3rd party)
- [ ] Local training commands
- [ ] Differential Privacy
- [ ] Federated Ensemble Support
- [ ] Multi-Key Homomorphic Encryption
- [ ] SecAgg (no trusted 3rd party)
- [ ] Model Quantization

##### ADDITIONAL FEATURES

The following features could help assess privacy and security guarantees:

- [ ] Adversarial Attacks
- [ ] Poisoning Attacks
- [ ] Reconstruction Attacks

___

### Dependencies

Made with Julia v1.6.1 and the following packages

- BSON 0.3.3
- CUDA 3.3.4
- Flux 0.12.4
- Nettle 0.5.1
- Primes 0.5.0
___

### Some References:

Cryptographic Methods

- [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Practical Secure Aggregation
for Privacy-Preserving Machine Learning](https://eprint.iacr.org/2017/281.pdf)
- [Privacy-Preserving Federated Learning Based on Multi-Key Homomorphic Encryption](https://arxiv.org/pdf/2104.06824.pdf)
- [Efficient Multi-Key Homomorphic Encryption
with Packed Ciphertexts with Application
to Oblivious Neural Network Inference](https://eprint.iacr.org/2019/524.pdf)
- [A Pragmatic Introduction to
Secure Multi-Party Computation](https://securecomputation.org/docs/pragmaticmpc.pdf)

Adversarial Methods

- [Deep Models Under the GAN: Information Leakage from
Collaborative Deep Learning](https://export.arxiv.org/pdf/1702.07464)
- [Deep Leakage from Gradients](https://hanlab.mit.edu/projects/dlg/assets/NeurIPS19_deep_leakage_from_gradients.pdf)
- [The Secret Sharer: Evaluating and Testing Unintended Memorization in Neural Networks](https://www.usenix.org/system/files/sec19-carlini.pdf)
- [Analyzing Federated Learning through an Adversarial Lens](https://www.princeton.edu/~pmittal/publications/bhagoji-icml19.pdf)

Federated Learning Methods

- [Advances and Open Problems in Federated Learning](https://arxiv.org/abs/1912.04977v3)
