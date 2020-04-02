# frozen_string_literal: true

module Keycloak
  module BaseClient
    def headers(access_token)
      {
        Authorization: "Bearer #{access_token}",
        content_type: :json,
        accept: :json
      }
    end

    def execute_http
      yield
    rescue RestClient::Exceptions::Timeout
      raise
    rescue RestClient::ExceptionWithResponse => e
      http_error(e)
    end

    private

    def http_error(error)
      raise KeycloakException, error
    end
  end
end
