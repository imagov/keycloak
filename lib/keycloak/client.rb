# frozen_string_literal: true

module Keycloak
  class Client
    attr_accessor :realm, :auth_server_url
    attr_reader :client_id, :secret, :configuration, :public_key

    def initialize(options = nil)
      return if options.nil?

      @options = options
      @realm = options[:realm]
      @auth_server_url = options[:auth_server_url]
      @client_id = options[:resource]
      @secret = options[:credentials][:secret]
      @public_key = options[:realm_public_key]

      @realm_client = Keycloak::RealmClient.new(@realm, server_url: @auth_server_url)
    end

    def get_token(user, password, client_id = '', secret = '')
      setup_module

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'username' => user,
                  'password' => password,
                  'grant_type' => 'password' }

      mount_request_token(payload)
    end

    def get_token_by_code(code, redirect_uri, client_id = '', secret = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'code' => code,
                  'grant_type' => 'authorization_code',
                  'redirect_uri' => redirect_uri }

      mount_request_token(payload)
    end

    def get_token_by_exchange(issuer, issuer_token, client_id = '', secret = '', token_endpoint = '')
      setup_module

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      token_endpoint = @configuration['token_endpoint'] if isempty?(token_endpoint)

      payload = { 'client_id' => client_id, 'client_secret' => secret, 'audience' => client_id, 'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token', 'subject_issuer' => issuer, 'subject_token' => issuer_token }
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      request = -> do
        RestClient.post(token_endpoint, payload, header){|response, _request, _result|
          response.body
        }
      end
      exec_request request
    end

    def get_userinfo_issuer(access_token = '', userinfo_endpoint = '')
      verify_setup

      userinfo_endpoint = @configuration['userinfo_endpoint'] if isempty?(userinfo_endpoint)

      access_token = token['access_token'] if access_token.empty?
      payload = { 'access_token' => access_token }
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      request = -> do
        RestClient.post(userinfo_endpoint, payload, header){ |response, _request, _result|
          response.body
        }
      end

      exec_request request
    end

    def get_token_by_refresh_token(refresh_token = '', client_id = '', secret = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      refresh_token = token['refresh_token'] if refresh_token.empty?

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'refresh_token' => refresh_token,
                  'grant_type' => 'refresh_token' }

      mount_request_token(payload)
    end

    def get_token_by_client_credentials(client_id = '', secret = '')
      setup_module

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'grant_type' => 'client_credentials' }

      mount_request_token(payload)
    end

    def get_token_introspection(token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      token = self.token['access_token'] if isempty?(token)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      payload = { 'token' => token }

      authorization = Base64.strict_encode64("#{client_id}:#{secret}")
      authorization = "Basic #{authorization}"

      header = { 'Content-Type' => 'application/x-www-form-urlencoded',
                'authorization' => authorization }

      _request = -> do
        RestClient.post(introspection_endpoint, payload, header){|response, request, result|
          case response.code
          when 200..399
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def url_login_redirect(redirect_uri, response_type = 'code', client_id = '', authorization_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      authorization_endpoint = @configuration['authorization_endpoint'] if isempty?(authorization_endpoint)

      p = URI.encode_www_form(response_type: response_type, client_id: client_id, redirect_uri: redirect_uri)
      "#{authorization_endpoint}?#{p}"
    end

    def logout(redirect_uri = '', refresh_token = '', client_id = '', secret = '', end_session_endpoint = '')
      verify_setup

      if token || !refresh_token.empty?

        refresh_token = token['refresh_token'] if refresh_token.empty?
        client_id = @client_id if isempty?(client_id)
        secret = @secret if isempty?(secret)
        end_session_endpoint = @configuration['end_session_endpoint'] if isempty?(end_session_endpoint)

        payload = { 'client_id' => client_id,
                    'client_secret' => secret,
                    'refresh_token' => refresh_token }

        header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

        final_url = if redirect_uri.empty?
                      end_session_endpoint
                    else
                      "#{end_session_endpoint}?#{URI.encode_www_form(redirect_uri: redirect_uri)}"
                    end

        _request = -> do
          RestClient.post(final_url, payload, header){ |response, request, result|
            case response.code
            when 200..399
              true
            else
              response.return!
            end
          }
        end

        exec_request _request
      else
        true
      end
    end

    def get_userinfo(access_token = '', userinfo_endpoint = '')
      verify_setup

      access_token = token['access_token'] if access_token.empty?
      userinfo_endpoint = @configuration['userinfo_endpoint'] if isempty?(userinfo_endpoint)

      payload = { 'access_token' => access_token }

      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      _request = -> do
        RestClient.post(userinfo_endpoint, payload, header){ |response, request, result|
          case response.code
          when 200
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def url_user_account
      verify_setup

      "#{@auth_server_url}/realms/#{@realm}/account"
    end

    def has_role?(user_role, access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      if !Keycloak.validate_token_when_call_has_role || user_signed_in?(access_token, client_id, secret, introspection_endpoint)
        dt = decoded_access_token(access_token)[0]
        dt = dt['resource_access'][client_id]
        unless dt.nil?
          dt['roles'].each do |role|
            return true if role.to_s == user_role.to_s
          end
        end
      end
      false
    end

    def has_realm_role?(user_role, access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      if !Keycloak.validate_token_when_call_has_role || user_signed_in?(access_token, client_id, secret, introspection_endpoint)
        dt = decoded_access_token(access_token)[0]
        dt = dt['realm_access']
        unless dt.nil?
          dt['roles'].each do |role|
            return true if role.to_s == user_role.to_s
          end
        end
      end
      false
    end

    def realm_roles(access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      if !Keycloak.validate_token_when_call_has_role || user_signed_in?(access_token, client_id, secret, introspection_endpoint)
        dt = decoded_access_token(access_token)[0]
        dt = dt['realm_access']
        return dt['roles'].map(&:strip) unless dt.nil?
      end
      return []
    end

    def user_signed_in?(access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      begin
        JSON(get_token_introspection(access_token, client_id, secret, introspection_endpoint))['active'] === true
      rescue => e
        if e.class < Keycloak::KeycloakException
          raise
        else
          false
        end
      end
    end

    def get_attribute(attributeName, access_token = '')
      verify_setup

      attr = decoded_access_token(access_token)[0]
      attr[attributeName]
    end

    def token
      if !Keycloak.proc_cookie_token.nil?
        JSON Keycloak.proc_cookie_token.call
      else
        raise Keycloak::ProcCookieTokenNotDefined
      end
    end

    def external_attributes
      if !Keycloak.proc_external_attributes.nil?
        Keycloak.proc_external_attributes.call
      else
        raise Keycloak::ProcExternalAttributesNotDefined
      end
    end

    def decoded_access_token(access_token = '')
      access_token = token["access_token"] if access_token.empty?
      JWT.decode access_token, @public_key, false, { :algorithm => 'RS256' }
    end

    def decoded_refresh_token(refresh_token = '')
      refresh_token = token["access_token"] if refresh_token.empty?
      JWT.decode refresh_token, @public_key, false, { :algorithm => 'RS256' }
    end

    private

    KEYCLOACK_CONTROLLER_DEFAULT = 'session'.freeze

    def get_installation
      get_installation_from_file if @options.nil?
      openid_configuration
    end

    def get_installation_from_file
      if File.exists?(Keycloak.installation_file)
        installation = JSON File.read(Keycloak.installation_file)
        @realm = installation["realm"]
        @client_id = installation["resource"]
        @secret = installation["credentials"]["secret"]
        @public_key = installation["realm-public-key"]
        @auth_server_url = installation["auth-server-url"]
      else
        raise "#{Keycloak.installation_file} and relm settings not found." if isempty?(Keycloak.realm) || isempty?(Keycloak.auth_server_url)

        @realm = Keycloak.realm
        @auth_server_url = Keycloak.auth_server_url
      end
    end

    def verify_setup
      get_installation if @configuration.nil?
    end

    def setup_module
      Keycloak.proxy ||= ''
      Keycloak.keycloak_controller ||= KEYCLOACK_CONTROLLER_DEFAULT
      Keycloak.validate_token_when_call_has_role ||= false
      get_installation
    end

    def exec_request(proc_request)
      if Keycloak.explode_exception
        proc_request.call
      else
        begin
          proc_request.call
        rescue RestClient::ExceptionWithResponse => err
          err.response
        end
      end
    end

    def openid_configuration
      RestClient.proxy = Keycloak.proxy unless isempty?(Keycloak.proxy)
      config_url = "#{@auth_server_url}/realms/#{@realm}/.well-known/openid-configuration"
      _request = -> do
        RestClient.get config_url
      end
      response = exec_request _request
      if response.code == 200
        @configuration = JSON response.body
      else
        response.return!
      end
    end

    def mount_request_token(payload)
      header = {'Content-Type' => 'application/x-www-form-urlencoded'}

      _request = -> do
        RestClient.post(@configuration['token_endpoint'], payload, header){|response, request, result|
          case response.code
          when 200
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def decoded_id_token(idToken = '')
      tk = self.token
      idToken = tk["id_token"] if idToken.empty?
      if idToken
        @decoded_id_token = JWT.decode idToken, @public_key, false, { :algorithm => 'RS256' }
      end
    end
  end
end
