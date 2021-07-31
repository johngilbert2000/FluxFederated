using Sockets: TCPServer
using Flux: destructure, params

"""
  `fedavg!(models_dict::Dict{String, Any}, round_id::String)` -> Flux model

Averages models stored at `models_dict[round_id]`
Deletes those models from `models_dict`
Returns averaged model

Example:
```
# Let m1, m2, m3 be Flux models
models_dict = Dict("some_id" => [m1, m2, m3])
averaged_model = fedavg!(models_dict, "some_id")
```
"""
function fedavg!(models_dict::Dict{String, Any}, round_id::String)
  models = models_dict[round_id]
  local restructure

  # Obtain model weights
  Ws = []
  for model in models
    W, restructure = destructure(model)
    push!(Ws, W)
  end

  # Average weights and form new model
  average(X) = sum(X) / length(X)
  averaged_model = restructure(average(Ws))

  # Remove used models from `model_dict`
  delete!(models_dict, round_id)

  return averaged_model
end


"""
  `update_model(server_model, client_model, learning_rate = 0.1)`

Obtains weighted average of two models and returns resulting model
"""
function update_model(server_model, client_model, learning_rate = 0.1)
  server_W, restructure = destructure(server_model)
  client_W, restructure = destructure(client_model)

  server_degree = Float32(1 - learning_rate)
  client_degree = Float32(learning_rate)

  result_W = (server_W .* server_degree) .+ (client_W .* client_degree)
  return restructure(result_W) # resulting model
end


"""
  `establish_round_id(con::TCPSocket, shared_key::Bytes)`

Establishes Round ID for given client
"""
function establish_round_id(con::TCPSocket, shared_key::Bytes)
  # TODO
  return "not_implemented"
end

"""
  `serve_model(server::TCPServer, model, round_len=3, learning_rate=0.1, verbose=true)`

Sends Flux model to clients, asynchronously

`round_len`: number of clients per round
`learning_rate`: degree that averaged client models replace server model per round
`verbose`: if true, print parameter information
"""
function serve_model(server::TCPServer, model, round_len = 3, learning_rate = 0.1, verbose=true)
  num_connected = 0
  client_models = Dict{String, Any}()

  while true
    con = accept(server)
    if isopen(con)
      num_connected += 1
      println("Clients connected: $num_connected")
    end

    @async while isopen(con)
      try
        # Establish AES-256 Key
        shared_key = handshake_server(con)

        # Securely send model to client
        model_bytes = model_to_bytes(model)
        secure_send_bytes(con, model_bytes, shared_key)

        # Establish Round ID
        round_id = establish_round_id(con, shared_key)

        # Receive Updated Model
        client_update_bytes = secure_receive_bytes(con, shared_key)
        client_update = model_from_bytes(client_update_bytes)

        # Store Updated Model
        if round_id in keys(client_models)
          push!(client_models[round_id], client_update)
        else
          client_models[round_id] = [client_update]
        end

        # Close Connection
        num_connected -= 1
        close(con)
        println("Clients connected: $num_connected")

        # Check number of models stored for each `round_id`
        for round_id in keys(client_models)
          if verbose
            println("Checking Round ID: $round_id (length: $(length(client_models[round_id])))")
          end

          # Average models, if models received >= round_len
          if length(client_models[round_id]) >= round_len
            averaged_model = fedavg!(client_models, round_id)
            model = update_model(model, averaged_model, learning_rate)

            if verbose
              println("Averaging Round ID: $round_id")
              println("\nAveraged Client Params\n", params(averaged_model))
              println("\nUpdated Model Params\n", params(model))
            end
          end
        end

      catch err
        close(con)
        throw(err)
      end
    end
  end
end

