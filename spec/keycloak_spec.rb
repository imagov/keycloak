# frozen_string_literal: true

require 'spec_helper'
require 'yaml'

RSpec.describe Keycloak do
  it 'has a version number' do
    expect(Keycloak::VERSION).not_to be nil
  end

  describe 'module configuration' do
    describe '.installation_file=' do
      it 'raise an error if given file does not exist' do
        expect{ Keycloak.installation_file = 'random/file.json' }.to raise_error(Keycloak::InstallationFileNotFound)
      end
    end

    describe '.installation_file' do
      it 'return default installation file' do
        expect(Keycloak.installation_file).to eq(Keycloak::KEYCLOAK_YAML_FILE)
      end

      it 'return configuration' do
        url = 'http://localhost:8180/auth'
        secret = '6cf4a5d2-8704-4451-86d9-c1c84e1341f1'
        installation = YAML.load_file(Keycloak.installation_file)
        expect(installation['auth-server-url']).to eq(url)
        expect(installation['credentials']['secret']).to eq(secret)
      end

      it 'return custom installation file location if previously set' do
        file_path = 'spec/fixtures/test_installation.yml'
        Keycloak.installation_file = file_path
        expect(Keycloak.installation_file).to eq(file_path)
      end
    end
  end
end
