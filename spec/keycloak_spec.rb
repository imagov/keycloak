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
        expect(Keycloak.installation_file).to eq(Keycloak::KEYCLOAK_JSON_FILE)
      end

      it 'should return custom installation file location if previously set' do
        Keycloak.installation_file = 'spec/fixtures/test_installation.json'
        expect(Keycloak.installation_file).to eq('spec/fixtures/test_installation.json')
      end
    end
  end
end
