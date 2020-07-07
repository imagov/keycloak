# frozen_string_literal: true

module Keycloak
  class ManagerClient < Client
    include BaseClient

    def initialize(configuration, user_manager:)
      super(configuration)
      @user_manager = user_manager
    end

    def create_user!(user_representation)
      save(user_representation)
    end

    def save(user_representation)
      response = execute_http do
        RestClient::Resource.new(users_url).post(
          user_representation.to_json, headers(access_token_for_manager)
        )
      end
      response
    end


    def add_roles_to_user(user_id:, roles:)
      roles_mappings = JSON.parse(available_roles_for_user(user_id: user_id)).select {|role| roles.include? role['name']}
      response = execute_http do
        RestClient::Resource.new(roles_url(id: user_id)).post(roles_mappings.to_json, headers(access_token_for_manager))
      end
      response
    end

    def available_roles_for_user(user_id:)
      response = execute_http do
        RestClient::Resource.new(roles_url(id: user_id, available: true)).get(headers(access_token_for_manager))
      end
      response.body
    end

    private

    def manager_name
      @user_manager[:username]
    end

    def manager_password
      @user_manager[:password]
    end

    def access_token_for_manager
      token_json = get_token(manager_name, manager_password)
      JSON.parse(token_json)['access_token']
    end

    def users_url(id: nil)
      if id
        "#{@realm_client.realm_admin_url}/users/#{id}"
      else
        "#{@realm_client.realm_admin_url}/users"
      end
    end

    def roles_url(id:, available: false)
      url = users_url(id: id)
      if available
        "#{url}/role-mappings/realm/available"
      else
        "#{url}/role-mappings/realm"
      end
    end
  end
end
