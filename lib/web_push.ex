defmodule WebPush do
  @moduledoc """
  Module to send web push notifications with an encrypted payload.
  """

  alias WebPush.Crypto

  defmacro __using__(opts \\ []) do
    quote bind_quoted: [opts: opts] do
      @opt_app Keyword.fetch!(opts, :otp_app)
      @adapter Keyword.fetch!(opts, :adapter)

      def vapid_public_key, do: Keyword.get(config(), :vapid_public_key)
      def vapid_private_key, do: Keyword.get(config(), :vapid_private_key)
      def vapid_subject, do: Keyword.get(config(), :vapid_subject)

      def send_notification(subscription, message) when is_binary(message) do
        WebPush.send_notification(
          @adapter,
          %{
            vapid_subject: vapid_subject(),
            vapid_public_key: vapid_public_key(),
            vapid_private_key: vapid_private_key()
          },
          subscription,
          message
        )
      end

      defp config, do: Application.fetch_env!(@otp_app, __MODULE__)
    end
  end

  @doc false
  def send_notification(adapter, keys, subscription, message) do
    vapid_subject = keys.vapid_subject
    vapid_public_key = Crypto.url_decode(keys.vapid_public_key)
    vapid_private_key = Crypto.url_decode(keys.vapid_private_key)

    %{endpoint: endpoint, keys: %{p256dh: p256dh, auth: auth}} = subscription

    encrypted_payload = Crypto.encrypt_payload(message, p256dh, auth)

    signed_jwt =
      Crypto.sign_json_web_token(endpoint, vapid_public_key, vapid_private_key, vapid_subject)

    adapter.call(%{
      endpoint: endpoint,
      payload: encrypted_payload.ciphertext,
      headers: [
        {"Authorization", "WebPush #{signed_jwt}"},
        {"Content-Encoding", "aesgcm"},
        {"Content-Length", "#{byte_size(encrypted_payload.ciphertext)}"},
        {"Content-Type", "application/octet-stream"},
        {"Crypto-Key",
         "dh=#{Crypto.url_encode(encrypted_payload.local_public_key)};p256ecdsa=#{Crypto.url_encode(vapid_public_key)}"},
        {"Encryption", "salt=#{Crypto.url_encode(encrypted_payload.salt)}"},
        {"TTL", "60"}
      ]
    })
  end
end
