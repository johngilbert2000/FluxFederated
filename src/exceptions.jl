
struct ConnectionError <: Exception
  msg::String
end

function Base.showerror(io::IO, err::ConnectionError)
  print(io, "ConnectionError: ", err.msg)
end


