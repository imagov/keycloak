require "spec_helper"

RSpec.describe Keycloak::ManagerClient do
  describe 'ManagerClient setup' do
    describe 'initialize' do
      before do
        @a_realm = 'irrelevant_realm'
        @auth_server_url = 'irrelevant_url'
        @a_resource = 'irrelevant_resource'
        @a_secret = 'irrelevant_secret'
        @a_public_key = 'irrelevant_public_key'
        @properties = {
          realm: @a_realm,
          auth_server_url: @auth_server_url,
          resource: @a_resource,
          credentials: { secret: @a_secret },
          realm_public_key: @a_public_key
        }
      end

      it 'should set properties' do
        @client = Keycloak::ManagerClient.new(@properties, user_manager: {
          username: 'irrelevant_username',
          password: 'irrelevant_password'
        })

        expect(@client.realm).to eq(@a_realm)
        expect(@client.auth_server_url).to eq(@auth_server_url)
        expect(@client.client_id).to eq(@a_resource)
        expect(@client.secret).to eq(@a_secret)
        expect(@client.public_key).to eq(@a_public_key)
      end
    end
  end
end
