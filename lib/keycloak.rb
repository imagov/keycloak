require 'keycloak/version'
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

require_relative 'keycloak/base_client'
require_relative 'keycloak/realm_client'
require_relative 'keycloak/client'
require_relative 'keycloak/client_manager'

def isempty?(value)
  value.respond_to?(:empty?) ? !!value.empty? : !value
end

module Keycloak
  OLD_KEYCLOAK_JSON_FILE = 'keycloak.json'.freeze
  KEYCLOAK_JSON_FILE = 'config/keycloak.json'.freeze

  class << self
    attr_accessor :proxy, :generate_request_exception, :keycloak_controller,
                  :proc_cookie_token, :proc_external_attributes,
                  :realm, :auth_server_url, :validate_token_when_call_has_role
  end

  def self.explode_exception
    Keycloak.generate_request_exception = true if Keycloak.generate_request_exception.nil?
    Keycloak.generate_request_exception
  end

  def self.installation_file
    @installation_file ||= if File.exist?(KEYCLOAK_JSON_FILE)
                             KEYCLOAK_JSON_FILE
                           else
                             OLD_KEYCLOAK_JSON_FILE
                           end
  end

  def self.installation_file=(file = nil)
    raise InstallationFileNotFound unless file.instance_of?(String) && File.exist?(file)

    @installation_file = file || KEYCLOAK_JSON_FILE
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
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      generic_delete("users/#{id}/consents/#{client_id}", nil, nil, access_token)
    end

    def self.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      generic_put("users/#{id}/execute-actions-email", { redirect_uri: redirect_uri, client_id: client_id }, actions, access_token)
    end

    def self.get_role_mappings(id, access_token = nil)
      generic_get("users/#{id}/role-mappings", nil, access_token)
    end

    def self.get_groups(query_parameters = nil, access_token = nil)
      generic_get("groups/", query_parameters, access_token)
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
      client = JSON get_clients({ clientId: client_id }, access_token)

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
        if isempty?(access_token)
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

    def self.get_users(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda {|token|
        Keycloak::Admin.get_users(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.get_groups(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        Keycloak::Admin.get_groups(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.change_password(user_id, redirect_uri = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda {|token|
        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("users/#{user_id}/execute-actions-email"),
                                 { redirect_uri: redirect_uri, client_id: client_id },
                                 ['UPDATE_PASSWORD'],
                                 'PUT')
      }

      default_call(proc, client_id, secret)
    end

    def self.forgot_password(user_login, redirect_uri = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      user = get_user_info(user_login, true, client_id, secret)
      change_password(user['id'], redirect_uri, client_id, secret)
    end

    def self.get_logged_user_info(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda {|token|
        userinfo = JSON Keycloak::Client.get_userinfo
        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("users/#{userinfo['sub']}"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_user_info(user_login, whole_word = false, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

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

      default_call(proc, client_id, secret)
    end

    def self.exists_name_or_email(value, user_id = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      begin
        usuario = Keycloak::Internal.get_user_info(value, true, client_id, secret)
        if user_id.empty? || user_id != usuario['id']
          !isempty?(usuario)
        else
          false
        end
      rescue StandardError
        false
      end
    end

    def self.logged_federation_user?(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)
      info = get_logged_user_info(client_id, secret)
      info['federationLink'] != nil
    end

    def self.create_simple_user(username, password, email, first_name, last_name, realm_roles_names, client_roles_names, proc = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      begin
        username.downcase!
        user = get_user_info(username, true, client_id, secret)
        new_user = false
      rescue Keycloak::UserLoginNotFound
        new_user = true
      rescue
        raise
      end

      proc_default = lambda { |token|
        user_representation = { username: username,
                                email: email,
                                firstName: first_name,
                                lastName: last_name,
                                enabled: true }

        if !new_user || Keycloak.generic_request(token["access_token"],
                                                Keycloak::Admin.full_url("users/"),
                                                nil, user_representation, 'POST')

          user = get_user_info(username, true, client_id, secret) if new_user

          credential_representation = { type: "password",
                                        temporary: false,
                                        value: password }

          if user['federationLink'] != nil || Keycloak.generic_request(token["access_token"],
                                                                       Keycloak::Admin.full_url("users/#{user['id']}/reset-password"),
                                                                       nil, credential_representation, 'PUT')

            client = JSON Keycloak.generic_request(token["access_token"],
                                                   Keycloak::Admin.full_url("clients/"),
                                                   { clientId: client_id }, nil, 'GET')

            if client_roles_names.count > 0
              roles = []
              client_roles_names.each do |r|
                unless isempty?(r)
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
            end

            if realm_roles_names.count > 0
              roles = []
              realm_roles_names.each do |r|
                unless isempty?(r)
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
            else
              true
            end
          end
        end
      }

      if default_call(proc_default, client_id, secret)
        proc.call user unless proc.nil?
      end
    end

    def self.create_starter_user(username, password, email, client_roles_names, proc = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)
      Keycloak::Internal.create_simple_user(username, password, email, '', '', [], client_roles_names, proc, client_id, secret)
    end

    def self.get_client_roles(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token['access_token'])

        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_client_user_roles(user_id, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token["access_token"])
        Keycloak::Admin.get_effective_client_level_role_composite_user(user_id, client[0]['id'], token["access_token"])
      }

      default_call(proc, client_id, secret)
    end

    def self.has_role?(user_id, user_role, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      roles = JSON get_client_user_roles(user_id, client_id, secret)
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

      def self.default_call(proc, client_id = '', secret = '')
        begin
          tk = nil
          resp = nil

          Keycloak::Client.get_installation

          client_id = Keycloak::Client.client_id if isempty?(client_id)
          secret = Keycloak::Client.secret if isempty?(secret)

          payload = { 'client_id' => client_id,
                      'client_secret' => secret,
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
            payload = { 'client_id' => client_id,
                        'client_secret' => secret,
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
      when 400..499
        response.return!
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
