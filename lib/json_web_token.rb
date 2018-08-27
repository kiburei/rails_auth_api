class JsonWebToken
  class << self
    # Token expiration time
    def encode(payload, exp = 2.hours.from_now)
      payload[:exp] = exp.to_i
      puts payload[:exp]
      # Encode user data(payload) with secret key
      JWT.encode(payload, Rails.application.secrets.secret_key_base)
    end

    def decode(token)
      # decode user data token
      body = JWT.decode(token, Rails.application.secrets.secret_key_base)[0]
      HashWithIndifferentAccess.new body

      # rails error
    rescue JWT::ExpiredSignature, JWT::VerificationError => e
      raise ExceptionHandler::ExpiredSignature, e.message
    rescue JWT::DecodeEror, JWR::VerificationError => e
      raise ExceptionHandler::DecodeEror, e.message
    end
  end
end
