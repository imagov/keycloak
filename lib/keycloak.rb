require 'keycloak/version'
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

module Keycloak
  class << self
    attr_accessor :proxy, :generate_request_exception, :keycloak_controller,
                  :proc_cookie_token, :proc_external_attributes
  end


  def self.explode_exception
    if Keycloak.generate_request_exception == nil
      Keycloak.generate_request_exception = true
    end
    Keycloak.generate_request_exception
  end

  module Client
    class << self
      attr_reader :realm, :url, :client_id, :auth_server_url,
                  :secret, :configuration, :public_key
    end

    KEYCLOAK_JSON_FILE = 'keycloak.json'

    def self.get_token(user, password)
      setup_module

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'username' => user,
                  'password' => password,
                  'grant_type' => 'password' }

      mount_request_token(payload)
    end

    def self.get_token_by_code(code, redirect_uri)
      verify_setup

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'code' => code,
                  'grant_type' => 'authorization_code',
                  'redirect_uri' => redirect_uri }

      mount_request_token(payload)
    end

    def self.get_token_by_refresh_token(refresh_token = '')
      verify_setup

      refresh_token = self.token['refresh_token'] if refresh_token.empty?

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'refresh_token' => refresh_token,
                  'grant_type' => 'refresh_token' }

      mount_request_token(payload)
    end

    def self.get_token_by_client_credentials(client_id = '', secret = '')
      setup_module

      client_id = @client_id if client_id.empty?
      secret = @secret if secret.empty?

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'grant_type' => 'client_credentials' }

      mount_request_token(payload)
    end

    def self.get_token_introspection(token = '')
      verify_setup

      token = self.token["access_token"] if token.empty?

      payload = { 'token' => token }

      authorization = Base64.strict_encode64("#{@client_id}:#{@secret}")
      authorization = "Basic #{authorization}"

      header = {'Content-Type' => 'application/x-www-form-urlencoded',
                'authorization' => authorization}

      _request = -> do
        RestClient.post(@configuration['token_introspection_endpoint'], payload, header){|response, request, result|
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

    def self.url_login_redirect(redirect_uri, response_type = 'code')
      verify_setup

      p = URI.encode_www_form({ response_type: response_type, client_id: @client_id, redirect_uri: redirect_uri })
      "#{@configuration['authorization_endpoint']}?#{p}"
    end

    def self.logout(redirect_uri = '', refresh_token = '')
      verify_setup

      if self.token || !refresh_token.empty?

        refresh_token = self.token['refresh_token'] if refresh_token.empty?

        payload = { 'client_id' => @client_id,
                    'client_secret' => @secret,
                    'refresh_token' => refresh_token
              }

        header = {'Content-Type' => 'application/x-www-form-urlencoded'}

        if redirect_uri.empty?
          final_url = @configuration['end_session_endpoint']
        else
          final_url = "#{@configuration['end_session_endpoint']}?#{URI.encode_www_form({ redirect_uri: redirect_uri })}"
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

    def self.get_userinfo(access_token = '')
      verify_setup

      access_token = self.token["access_token"] if access_token.empty?

      payload = { 'access_token' => access_token }

      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      _request = -> do
        RestClient.post(@configuration['userinfo_endpoint'], payload, header){ |response, request, result|
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

    def self.url_user_account
      verify_setup

      "#{@url}/realms/#{@realm}/account"
    end

    def self.has_role?(user_role, access_token = '')
      verify_setup

      if user_signed_in?(access_token)
        dt = decoded_access_token(access_token)[0]
        dt = dt["resource_access"][@client_id]
        if dt != nil
          dt["roles"].each do |role|
            return true if role.to_s == user_role.to_s
          end
          false
        else
          false
        end
      else
        false
      end
    end

    def self.user_signed_in?(access_token = '')
      verify_setup

      begin
        JSON(get_token_introspection(access_token))['active'] === true
      rescue => e
        if e.class < Keycloak::KeycloakException
          raise
        else
          false
        end
      end
    end

    def self.get_attribute(attributeName, access_token = '')
      verify_setup

      attr = decoded_access_token(access_token)[0]
      attr[attributeName]
    end

    def self.token
      if !Keycloak.proc_cookie_token.nil?
        JSON Keycloak.proc_cookie_token.call
      else
        raise Keycloak::ProcCookieTokenNotDefined
      end
    end

    def self.external_attributes
      if !Keycloak.proc_external_attributes.nil?
        Keycloak.proc_external_attributes.call
      else
        raise Keycloak::ProcExternalAttributesNotDefined
      end
    end

    private

      KEYCLOACK_CONTROLLER_DEFAULT = 'session'

      def self.get_installation
        if File.exists?(KEYCLOAK_JSON_FILE)
          installation = JSON File.read(KEYCLOAK_JSON_FILE)
          @realm = installation["realm"]
          @url = installation["auth-server-url"]
          @client_id = installation["resource"]
          @secret = installation["credentials"]["secret"]
          @public_key = installation["realm-public-key"]
          @auth_server_url = installation["auth-server-url"]
          openid_configuration
        else
          raise "#{KEYCLOAK_JSON_FILE} not found."
        end
      end

      def self.verify_setup
        get_installation if @configuration.nil?
      end

      def self.setup_module
        Keycloak.proxy ||= ''
        Keycloak.keycloak_controller ||= KEYCLOACK_CONTROLLER_DEFAULT
        get_installation
      end

      def self.exec_request(proc_request)
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

      def self.openid_configuration
        RestClient.proxy = Keycloak.proxy unless Keycloak.proxy.empty?
        config_url = "#{@url}/realms/#{@realm}/.well-known/openid-configuration"
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

      def self.mount_request_token(payload)
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

      def self.decoded_access_token(access_token = '')
        access_token = self.token["access_token"] if access_token.empty?
        JWT.decode access_token, @public_key, false, { :algorithm => 'RS256' }
      end

      def self.decoded_refresh_token(refresh_token = '')
        refresh_token = self.token["access_token"] if refresh_token.empty?
        JWT.decode refresh_token, @public_key, false, { :algorithm => 'RS256' }
      end

      def self.decoded_id_token(idToken = '')
        tk = self.token
        idToken = tk["id_token"] if idToken.empty?
        if idToken
          @decoded_id_token = JWT.decode idToken, @public_key, false, { :algorithm => 'RS256' }
        end
      end

  end

  # Os recursos desse module (admin) serão utilizadas apenas por usuários que possuem as roles do client realm-management
  module Admin
    class << self
    end

    def self.get_users(query_parameters = nil, access_token = nil)
      generic_get("users/", query_parameters, access_token)
    end

    def self.create_user(user_representation, access_token = nil)
      generic_post("users/", nil, user_representation, access_token)
    end

    def self.count_users(access_token = nil)
      generic_get("users/count/", nil, access_token)
    end

    def self.get_user(id, access_token = nil)
      generic_get("users/#{id}", nil, access_token)
    end

    def self.update_user(id, user_representation, access_token = nil)
      generic_put("users/#{id}", nil, user_representation, access_token)
    end

    def self.delete_user(id, access_token = nil)
      generic_delete("users/#{id}", nil, nil, access_token)
    end

    def self.revoke_consent_user(id, client_id = nil, access_token = nil)
      if client_id.nil?
        client_id = Keycloak::Client.client_id
      end
      generic_delete("users/#{id}/consents/#{client_id}", nil, nil, access_token)
    end

    def self.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
      if client_id.nil?
        client_id = Keycloak::Client.client_id
      end
      generic_put("users/#{id}/execute-actions-email", {:redirect_uri => redirect_uri, :client_id => client_id}, actions, access_token)
    end

    def self.get_role_mappings(id, access_token = nil)
      generic_get("users/#{id}/role-mappings", nil, access_token)
    end

    def self.get_clients(query_parameters = nil, access_token = nil)
      generic_get("clients/", query_parameters, access_token)
    end

    def self.get_all_roles_client(id, access_token = nil)
      generic_get("clients/#{id}/roles", nil, access_token)
    end

    def self.get_roles_client_by_name(id, role_name, access_token = nil)
      generic_get("clients/#{id}/roles/#{role_name}", nil, access_token)
    end

    def self.add_client_level_roles_to_user(id, client, role_representation, access_token = nil)
      generic_post("users/#{id}/role-mappings/clients/#{client}", nil, role_representation, access_token)
    end

    def self.delete_client_level_roles_from_user(id, client, role_representation, access_token = nil)
      generic_delete("users/#{id}/role-mappings/clients/#{client}", nil, role_representation, access_token)
    end

    def self.get_client_level_role_for_user_and_app(id, client, access_token = nil)
      generic_get("users/#{id}/role-mappings/clients/#{client}", nil, access_token)
    end

    def self.update_effective_user_roles(id, client_id, roles_names, access_token = nil)
      client = JSON get_clients({ clientId: client_id })

      user_roles = JSON get_client_level_role_for_user_and_app(id, client[0]['id'], access_token)

      roles = Array.new
      # Include new role
      roles_names.each do |r|
        if r && !r.empty?
          found = false
          user_roles.each do |ur|
            found = ur['name'] == r
            break if found
            found = false
          end
          if !found
            role = JSON get_roles_client_by_name(client[0]['id'], r, access_token)
            roles.push(role)
          end
        end
      end

      garbage_roles = Array.new
      # Exclude old role
      user_roles.each do |ur|
        found = false
        roles_names.each do |r|
          if r && !r.empty?
            found = ur['name'] == r
            break if found
            found = false
          end
        end
        if !found
          garbage_roles.push(ur)
        end
      end

      if garbage_roles.count > 0
        delete_client_level_roles_from_user(id, client[0]['id'], garbage_roles, access_token)
      end

      if roles.count > 0
        add_client_level_roles_to_user(id, client[0]['id'], roles, access_token)
      end
    end

    def self.reset_password(id, credential_representation, access_token = nil)
      generic_put("users/#{id}/reset-password", nil, credential_representation, access_token)
    end

    def self.get_effective_client_level_role_composite_user(id, client, access_token = nil)
      generic_get("users/#{id}/role-mappings/clients/#{client}/composite", nil, access_token)
    end

    # Generics methods

    def self.generic_get(service, query_parameters = nil, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, nil, 'GET')
    end

    def self.generic_post(service, query_parameters, body_parameter, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, body_parameter, 'POST')
    end

    def self.generic_put(service, query_parameters, body_parameter, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, body_parameter, 'PUT')
    end

    def self.generic_delete(service, query_parameters = nil, body_parameter = nil, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, body_parameter, 'DELETE')
    end

    private

      def self.effective_access_token(access_token)
        if access_token.blank?
          Keycloak::Client.token['access_token']
        else
          access_token
        end
      end

      def self.base_url
        Keycloak::Client.auth_server_url + "/admin/realms/#{Keycloak::Client.realm}/"
      end

      def self.full_url(service)
        base_url + service
      end

  end

  module Internal
    include Keycloak::Admin

    class << self
    end

    def self.get_users(query_parameters = nil)
      proc = lambda {|token|
        Keycloak::Admin.get_users(query_parameters, token["access_token"])
      }

      default_call(proc)
    end

    def self.change_password(user_id, redirect_uri = '')
      proc = lambda {|token|
        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("users/#{user_id}/execute-actions-email"),
                                 {:redirect_uri => redirect_uri, :client_id => Keycloak::Client.client_id},
                                 ['UPDATE_PASSWORD'],
                                 'PUT')
      }

      default_call(proc)
    end

    def self.forgot_password(user_login, redirect_uri = '')
      user = get_user_info(user_login, true)
      change_password(user['id'], redirect_uri)
    end

    def self.get_logged_user_info
      proc = lambda {|token|
        userinfo = JSON Keycloak::Client.get_userinfo
        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("users/#{userinfo['sub']}"),
                                 nil, nil, 'GET')
      }

      default_call(proc)
    end

    def self.get_user_info(user_login, whole_word = false)
      proc = lambda { |token|
        if user_login.index('@').nil?
          search = {:username => user_login}
        else
          search = {:email => user_login}
        end
        users = JSON Keycloak.generic_request(token["access_token"],
                                              Keycloak::Admin.full_url("users/"),
                                              search, nil, 'GET')
        users[0]
        if users.count.zero?
          raise Keycloak::UserLoginNotFound
        else
          efective_index = -1
          users.each_with_index do |user, i|
            if whole_word
              efective_index = i if user_login == user['username'] || user_login == user['email']
            else
              efective_index = 0
            end
            break if efective_index >= 0
          end

          if efective_index >= 0
            if whole_word
              users[efective_index]
            else
              users
            end
          else
            raise Keycloak::UserLoginNotFound
          end
        end
      }

      default_call(proc)
    end

    def self.exists_name_or_email(value, user_id = '')
      begin
        usuario = Keycloak::Internal.get_user_info(value, true)
        if user_id.empty? || user_id != usuario['id']
          usuario.present?
        else
          false
        end
      rescue StandardError
        false
      end
    end

    def self.logged_federation_user?
      info = get_logged_user_info
      info['federationLink'] != nil
    end

    def self.create_simple_user(username, password, email, first_name, last_name, realm_roles_names, client_roles_names, proc = nil)
      begin
        username.downcase!
        user = get_user_info(username, true)
        newUser = false
      rescue Keycloak::UserLoginNotFound
        newUser = true
      rescue
        raise
      end

      proc_default = lambda { |token|
        user_representation = { username: username,
                                email: email,
                                firstName: first_name,
                                lastName: last_name,
                                enabled: true }

        if !newUser || Keycloak.generic_request(token["access_token"],
                                                Keycloak::Admin.full_url("users/"),
                                                nil, user_representation, 'POST')

          user = get_user_info(username, true) if newUser

          credential_representation = { type: "password",
                                        temporary: false,
                                        value: password }

          if user['federationLink'] != nil || Keycloak.generic_request(token["access_token"],
                                                                       Keycloak::Admin.full_url("users/#{user['id']}/reset-password"),
                                                                       nil, credential_representation, 'PUT')

            client = JSON Keycloak.generic_request(token["access_token"],
                                                   Keycloak::Admin.full_url("clients/"),
                                                   { clientId: Keycloak::Client.client_id }, nil, 'GET')

            roles = []
            client_roles_names.each do |r|
              if r.present?
                role = JSON Keycloak.generic_request(token["access_token"],
                                                     Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles/#{r}"),
                                                     nil, nil, 'GET')
                roles.push(role)
              end
            end

            if roles.count > 0
              Keycloak.generic_request(token["access_token"],
                                       Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/clients/#{client[0]['id']}"),
                                       nil, roles, 'POST')
            end

            roles = []
            realm_roles_names.each do |r|
              if r.present?
                role = JSON Keycloak.generic_request(token["access_token"],
                                                     Keycloak::Admin.full_url("roles/#{r}"),
                                                     nil, nil, 'GET')
                roles.push(role)
              end
            end

            if roles.count > 0
              Keycloak.generic_request(token["access_token"],
                                       Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/realm"),
                                       nil, roles, 'POST')
            end
          end

        end
      }

      if default_call(proc_default)
        proc.call user unless proc.nil?
      end
    end

    def self.create_starter_user(username, password, email, client_roles_names, proc = nil)
      Keycloak::Internal.create_simple_user(username, password, email, '', '', [], client_roles_names, proc)
    end

    def self.get_client_roles
      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: Keycloak::Client.client_id }, token["access_token"])

        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles"),
                                 nil, nil, 'GET')
      }

      default_call(proc)
    end

    def self.get_client_user_roles(user_id)
      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: Keycloak::Client.client_id }, token["access_token"])
        Keycloak::Admin.get_effective_client_level_role_composite_user(user_id, client[0]['id'], token["access_token"])
      }

      default_call(proc)
    end

    def self.has_role?(user_id, user_role)
      roles = JSON get_client_user_roles(user_id)
      if !roles.nil?
        roles.each do |role|
          return true if role['name'].to_s == user_role.to_s
        end
        false
      else
        false
      end
    end

    protected

      def self.default_call(proc)
        begin
          tk = nil
          resp = nil

          Keycloak::Client.get_installation

          payload = { 'client_id' => Keycloak::Client.client_id,
                      'client_secret' => Keycloak::Client.secret,
                      'grant_type' => 'client_credentials' }

          header = {'Content-Type' => 'application/x-www-form-urlencoded'}

          _request = -> do
            RestClient.post(Keycloak::Client.configuration['token_endpoint'], payload, header){|response, request, result|
              case response.code
              when 200..399
                tk = JSON response.body
                resp = proc.call(tk)
              else
                response.return!
              end
            }
          end

          Keycloak::Client.exec_request _request
        ensure
          if tk
            payload = { 'client_id' => Keycloak::Client.client_id,
                        'client_secret' => Keycloak::Client.secret,
                        'refresh_token' => tk["refresh_token"] }

            header = {'Content-Type' => 'application/x-www-form-urlencoded'}
            _request = -> do
              RestClient.post(Keycloak::Client.configuration['end_session_endpoint'], payload, header){|response, request, result|
                case response.code
                when 200..399
                  resp if resp.nil?
                else
                  response.return!
                end
              }
            end
            Keycloak::Client.exec_request _request
          end
        end
      end

  end

  private

    def self.generic_request(access_token, uri, query_parameters, body_parameter, method)
      Keycloak::Client.verify_setup
      final_url = uri

      header = {'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => "Bearer #{access_token}"}

      if query_parameters
        parameters = URI.encode_www_form(query_parameters)
        final_url = final_url << '?' << parameters
      end

      case method.upcase
      when 'GET'
        _request = -> do
          RestClient.get(final_url, header){|response, request, result|
            rescue_response(response)
          }
        end
      when 'POST', 'PUT'
        header["Content-Type"] = 'application/json'
        parameters = JSON.generate body_parameter
        _request = -> do
          case method.upcase
          when 'POST'
            RestClient.post(final_url, parameters, header){|response, request, result|
              rescue_response(response)
            }
          else
            RestClient.put(final_url, parameters, header){|response, request, result|
              rescue_response(response)
            }
          end
        end
      when 'DELETE'
        _request = -> do
          if body_parameter
            header["Content-Type"] = 'application/json'
            parameters = JSON.generate body_parameter
            RestClient::Request.execute(method: :delete, url: final_url,
                          payload: parameters, headers: header) { |response, request, result|
              rescue_response(response)
            }
          else
            RestClient.delete(final_url, header) { |response, request, result|
              rescue_response(response)
            }
          end
        end
      else
        raise
      end

      _request.call

    end

    def self.rescue_response(response)
      case response.code
      when 200..399
        if response.body.empty?
          true
        else
          response.body
        end
      else
        if Keycloak.explode_exception
          response.return!
        else
          begin
            response.return!
          rescue RestClient::ExceptionWithResponse => err
            err.response
          rescue StandardError => e
            e.message
          end
        end
      end
    end
end

require 'keycloak/exceptions'