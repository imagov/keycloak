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
  end
end
