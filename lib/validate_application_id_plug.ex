defmodule PhoenixAlexa.ValidateApplicationId do
  import Plug.Conn

  @pubkey_schema Record.extract_all(from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  @subject_altname_id {2, 5, 29, 17}

  def init(applicationId), do: applicationId

  def call(conn, applicationId) do
    conn =
      conn
      |> assign(:valid_alexa_request, true)
      |> validate_application_id(applicationId)
      |> validate_timestamp()
      |> validate_signature_chain_url
      |> validate_signature()

    case conn.assigns.valid_alexa_request do
      true ->
        conn

      _ ->
        conn
        |> Plug.Conn.send_resp(400, ~s({"error": "Invalid application"}))
        |> halt
    end
  end

  def validate_timestamp(conn) do
    conn.params["request"]["timestamp"]
    |> DateTime.from_iso8601()
    |> within_allowed_time_window?
    |> update_alexa_validation(conn)

    conn
  end

  def validate_application_id(conn, applicationId) do
    matching = conn.body_params["session"]["application"]["applicationId"] == applicationId
    update_alexa_validation(matching, conn)
  end

  def validate_signature(conn) do
    raw_body = conn.private[:raw_body]

    conn
    |> get_req_header("signaturecertchainurl")
    |> Enum.at(0)
    |> retrieve_pem
    |> validate_pem(conn)
    |> update_alexa_validation(conn)
  end

  def validate_signature_chain_url(conn) do
    conn
    |> get_req_header("signaturecertchainurl")
    |> Enum.at(0)
    |> URI.parse()
    |> validate_uri
    |> update_alexa_validation(conn)
  end

  defp validate_uri(%URI{authority: "s3.amazonaws.com", scheme: "https", port: 443} = uri) do
    case Regex.run(~r|/echo.api/|, uri.path) do
      nil ->
        false

      _ ->
        true
    end
  end

  defp validate_uri(invalid_uri), do: false

  defp within_allowed_time_window?({:ok, timestamp, _offset}) do
    Timex.diff(DateTime.utc_now(), timestamp, :seconds) < 150
  end

  def update_alexa_validation(true, conn), do: conn

  def update_alexa_validation(false, conn) do
    conn = conn |> assign(:valid_alexa_request, false)
    conn
  end

  defp retrieve_pem(uri) do
    HTTPotion.get(uri)
  end

  defp validate_pem(pem, original_conn) do
    [signature] = get_req_header(original_conn, "signature")
    raw_body = original_conn.private[:raw_body]
    PhoenixAlexa.Certificate.valid?(signature, pem.body, raw_body)
  end
end
