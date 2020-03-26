require "spec_helper"

RSpec.describe Keycloak do
  it "has a version number" do
    expect(Keycloak::VERSION).not_to be nil
  end

  describe 'Module configuration' do
    describe '.installation_file=' do
      it 'should raise an error if given file does not exist' do
        expect{ Keycloak.installation_file = 'random/file.json' }.to raise_error(Keycloak::InstallationFileNotFound)
      end
    end

    describe '.installation_file' do
      it 'should return default installation file' do
        expect(Keycloak.installation_file).to eq(Keycloak::OLD_KEYCLOAK_JSON_FILE)
      end

      it 'should return custom installation file location if previously set' do
        Keycloak.installation_file = 'spec/fixtures/test_installation.json'
        expect(Keycloak.installation_file).to eq('spec/fixtures/test_installation.json')
      end
    end
  end

  describe 'Client setup' do
    describe 'initialize' do
      before do
        @a_realm = 'irrelevant_realm'
        @auth_server_url = 'irrelevant_url'
        @properties = {
          realm: @a_realm,
          auth_server_url: @auth_server_url,
          client_id: 'irrelevant_client_id',
          credentials: { secret: 'irrelevant_secret' },
          realm_public_key: 'irrelevant_public_key'
        }
      end

      it 'should set properties' do
        @client = Keycloak::Client.new(@properties)

        expect(@client.realm).to eq(@a_realm)
        expect(@client.auth_server_url).to eq(@auth_server_url)
      end

      it 'should initialize without properties' do
        expect { Keycloak::Client.new }.not_to raise_error
      end
    end
  end
end
