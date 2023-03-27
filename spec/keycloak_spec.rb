# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Keycloak do
  it 'has a version number' do
    expect(Keycloak::VERSION).not_to be nil
  end

  describe 'Module configuration' do
    describe '.installation_file=' do
      it 'should raise an error if given file does not exist' do
        expect{ Keycloak.installation_file = 'random/file.json' }.to raise_error(Keycloak::InstallationFileNotFound)
      end
    end
    
    describe '.installation_file' do
      # as the installation_file setting is memoized, we need to reset it between tests
      # setting it back to nil is not possible via Keycloak.installation_file = nil
      # so we have to reach in through 'instance_variable_set'
      before { Keycloak.instance_variable_set(:"@installation_file", nil) }

      context 'old vs. new' do
        before { allow(File).to receive(:exist?).with(Keycloak::KEYCLOAK_JSON_FILE).and_return(new_file_exists) }

        context 'the file at the new location exists' do
          let(:new_file_exists) { true }

          it 'should return default installation file' do
            expect(Keycloak.installation_file).to eq(Keycloak::KEYCLOAK_JSON_FILE)
          end
        end

        context 'the file at the new location does not exist' do
          let(:new_file_exists) { false }

          it 'should return the old default installation file' do
            expect(Keycloak.installation_file).to eq(Keycloak::OLD_KEYCLOAK_JSON_FILE)
          end
        end
      end

      context 'when it is explicitly set' do
        let(:expected_installation_file_location) { 'spec/fixtures/test_installation.json' }
        before { Keycloak.installation_file = expected_installation_file_location }

        it 'should return custom installation file location if previously set' do
          expect(Keycloak.installation_file).to eq(expected_installation_file_location)
        end
      end
    end
  end
end
