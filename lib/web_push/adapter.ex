defmodule WebPush.Adapter do
  @type env() :: %{
          endpoint: binary(),
          payload: binary(),
          headers: [{binary(), binary()}]
        }

  @callback call(env()) :: :ok | {:error, any()}
end
