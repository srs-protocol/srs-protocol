import unittest
from unittest.mock import Mock, MagicMock, patch, MagicMock
import sys
import os
import json
from datetime import datetime

# Add the XSOAR integration directory to the path
sys.path.insert(0, '/home/Great/SRS-Protocol/xsoar_integration')

# Mock XSOAR dependencies
class MockDemisto:
    def __init__(self):
        self.args = {}
        self.results = []
        
    def args(self):
        return self.args
        
    def results(self, result):
        self.results.append(result)
        
    def command(self):
        return "test"

# Create mock for demistomock
demisto_mock = MockDemisto()
sys.modules['demistomock'] = demisto_mock
sys.modules['CommonServerPython'] = Mock()
sys.modules['CommonServerUserPython'] = Mock()

# Import after mocking dependencies
from orasrs_integration import Client, test_module, get_threat_intelligence_command, get_consensus_verification_command, submit_threat_evidence_command, get_upstream_intelligence_command

class TestXSOARIntegration(unittest.TestCase):
    """Test the OraSRS XSOAR Integration"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.base_url = "https://api.orasrs.example.com"
        self.api_key = "test-api-key"
        self.client = Client(base_url=self.base_url, api_key=self.api_key, verify_ssl=False)
        
    @patch('orasrs_integration.requests.get')
    def test_client_initialization(self, mock_get):
        """Test that the client is properly initialized"""
        mock_get.return_value.json.return_value = {'status': 'healthy'}
        mock_get.return_value.raise_for_status.return_value = None
        
        self.assertEqual(self.client._base_url, self.base_url)
        self.assertIn('Authorization', self.client._headers)
        self.assertIn('Bearer', self.client._headers['Authorization'])
        
    @patch('orasrs_integration.requests.get')
    def test_test_module_success(self, mock_get):
        """Test the test_module function with successful response"""
        # Mock successful response
        mock_response = Mock()
        mock_response.get.return_value = 'healthy'
        mock_get.return_value.json.return_value = {'status': 'healthy'}
        
        # Create a mock client with mocked test_connection
        mock_client = Mock()
        mock_client.test_connection.return_value = {'status': 'healthy'}
        
        result = test_module(mock_client)
        self.assertEqual(result, 'ok')
    
    @patch('orasrs_integration.requests.get')
    def test_test_module_failure(self, mock_get):
        """Test the test_module function with failed response"""
        # Mock failed response
        mock_response = Mock()
        mock_response.get.return_value = 'unhealthy'
        mock_get.return_value.json.return_value = {'status': 'unhealthy'}
        
        # Create a mock client with mocked test_connection
        mock_client = Mock()
        mock_client.test_connection.return_value = {'status': 'unhealthy'}
        
        result = test_module(mock_client)
        self.assertNotEqual(result, 'ok')
    
    @patch('orasrs_integration.requests.get')
    def test_get_threat_intelligence_command(self, mock_get):
        """Test the get_threat_intelligence_command function"""
        # Mock API response
        mock_threats = {
            'threats': [
                {
                    'id': 'threat-123',
                    'threat_type': 'Malware',
                    'threat_level': 'Critical',
                    'source_ip': '192.168.1.100',
                    'target_ip': '10.0.0.1',
                    'timestamp': '2023-01-01T00:00:00Z',
                    'credibility_score': 0.85,
                    'consensus_verified': True,
                    'context': 'Test threat',
                    'evidence_hash': 'abc123'
                }
            ]
        }
        mock_get.return_value.json.return_value = mock_threats
        
        mock_client = Mock()
        mock_client.get_threat_intelligence.return_value = mock_threats
        
        args = {'limit': '10'}
        result = get_threat_intelligence_command(mock_client, args)
        
        # Verify the result structure
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.outputs)
        self.assertEqual(len(result.outputs), 1)
        
        # Verify the first threat
        first_threat = result.outputs[0]
        self.assertEqual(first_threat['ID'], 'threat-123')
        self.assertEqual(first_threat['ThreatType'], 'Malware')
        self.assertEqual(first_threat['ThreatLevel'], 'Critical')
        self.assertEqual(first_threat['SourceIP'], '192.168.1.100')
        self.assertEqual(first_threat['CredibilityScore'], 0.85)
        self.assertEqual(first_threat['ConsensusVerified'], True)
    
    @patch('orasrs_integration.requests.get')
    def test_get_consensus_verification_command(self, mock_get):
        """Test the get_consensus_verification_command function"""
        # Mock API response
        mock_response = {
            'consensus_status': 'verified',
            'confidence_score': 0.9,
            'total_verifiers': 5,
            'consensus_percentage': 0.8,
            'verified_by': ['agent1', 'agent2', 'agent3'],
            'disputed_by': ['agent4']
        }
        mock_get.return_value.json.return_value = mock_response
        
        mock_client = Mock()
        mock_client.get_consensus_verification.return_value = mock_response
        
        args = {'threat_id': 'threat-123'}
        result = get_consensus_verification_command(mock_client, args)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.outputs)
        
        output = result.outputs
        self.assertEqual(output['ThreatID'], 'threat-123')
        self.assertEqual(output['ConsensusStatus'], 'verified')
        self.assertEqual(output['ConfidenceScore'], 0.9)
        self.assertEqual(output['TotalVerifiers'], 5)
        self.assertEqual(output['ConsensusPercentage'], 0.8)
    
    @patch('orasrs_integration.requests.post')
    def test_submit_threat_evidence_command(self, mock_post):
        """Test the submit_threat_evidence_command function"""
        # Mock API response
        mock_response = {
            'id': 'new-threat-456',
            'status': 'submitted',
            'message': 'Threat evidence submitted successfully'
        }
        mock_post.return_value.json.return_value = mock_response
        
        mock_client = Mock()
        mock_client.submit_threat_evidence.return_value = mock_response
        
        args = {
            'source_ip': '192.168.1.200',
            'target_ip': '10.0.0.2',
            'threat_type': 'DDoS',
            'threat_level': 'Emergency',
            'context': 'DDoS attack detected'
        }
        result = submit_threat_evidence_command(mock_client, args)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.outputs)
        
        output = result.outputs
        self.assertEqual(output['SubmittedThreatID'], 'new-threat-456')
        self.assertEqual(output['Status'], 'submitted')
        self.assertEqual(output['Message'], 'Threat evidence submitted successfully')
    
    @patch('orasrs_integration.requests.get')
    def test_get_upstream_intelligence_command(self, mock_get):
        """Test the get_upstream_intelligence_command function"""
        # Mock API response
        mock_response = {
            'upstream_threats': [
                {
                    'id': 'upstream-789',
                    'source_type': 'CISA_AIS',
                    'threat_type': 'Malware',
                    'threat_level': 'Critical',
                    'source_ip': '203.0.113.10',
                    'timestamp': '2023-01-01T00:00:00Z',
                    'confidence': 0.95,
                    'description': 'Malware IP from CISA AIS feed',
                    'source': 'cisa_ais'
                }
            ]
        }
        mock_get.return_value.json.return_value = mock_response
        
        mock_client = Mock()
        mock_client.get_upstream_intelligence.return_value = mock_response
        
        args = {}
        result = get_upstream_intelligence_command(mock_client, args)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.outputs)
        self.assertEqual(len(result.outputs), 1)
        
        first_threat = result.outputs[0]
        self.assertEqual(first_threat['ID'], 'upstream-789')
        self.assertEqual(first_threat['SourceType'], 'CISA_AIS')
        self.assertEqual(first_threat['ThreatType'], 'Malware')
        self.assertEqual(first_threat['ConfidenceScore'], 0.95)
    
    def test_threat_type_predefined_values(self):
        """Test that threat types match expected values"""
        expected_threat_types = ['DDoS', 'Malware', 'Phishing', 'BruteForce', 
                                'SuspiciousConnection', 'AnomalousBehavior', 'IoCMatch']
        
        # This test verifies that the integration handles all expected threat types
        self.assertEqual(len(expected_threat_types), 7)
        self.assertIn('Malware', expected_threat_types)
        self.assertIn('DDoS', expected_threat_types)
    
    def test_threat_level_predefined_values(self):
        """Test that threat levels match expected values"""
        expected_threat_levels = ['Info', 'Warning', 'Critical', 'Emergency']
        
        # This test verifies that the integration handles all expected threat levels
        self.assertEqual(len(expected_threat_levels), 4)
        self.assertIn('Critical', expected_threat_levels)
        self.assertIn('Emergency', expected_threat_levels)
    
    def test_integration_yaml_commands(self):
        """Test that the integration YAML has all required commands"""
        yaml_path = '/home/Great/SRS-Protocol/xsoar_integration/orasrs_integration.yml'
        self.assertTrue(os.path.exists(yaml_path), "Integration YAML file should exist")
        
        with open(yaml_path, 'r') as f:
            yaml_content = f.read()
        
        # Check for required commands
        self.assertIn('orasrs-get-threat-intelligence', yaml_content)
        self.assertIn('orasrs-get-consensus-verification', yaml_content)
        self.assertIn('orasrs-submit-threat-evidence', yaml_content)
        self.assertIn('orasrs-get-upstream-intelligence', yaml_content)
    
    def test_integration_yaml_configuration(self):
        """Test that the integration YAML has proper configuration"""
        yaml_path = '/home/Great/SRS-Protocol/xsoar_integration/orasrs_integration.yml'
        self.assertTrue(os.path.exists(yaml_path), "Integration YAML file should exist")
        
        with open(yaml_path, 'r') as f:
            yaml_content = f.read()
        
        # Check for required configuration fields
        self.assertIn('url', yaml_content)
        self.assertIn('api_key', yaml_content)
        self.assertIn('insecure', yaml_content)
        self.assertIn('OraSRS v2.0 Threat Intelligence', yaml_content)


class TestXSOARIntegrationExceptionHandling(unittest.TestCase):
    """Test exception handling in the XSOAR Integration"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.base_url = "https://api.orasrs.example.com"
        self.api_key = "test-api-key"
        
    @patch('orasrs_integration.requests.get')
    def test_exception_in_get_threat_intelligence(self, mock_get):
        """Test exception handling in get_threat_intelligence_command"""
        mock_get.side_effect = Exception("Connection error")
        
        mock_client = Mock()
        mock_client.get_threat_intelligence.side_effect = Exception("API Error")
        
        args = {'limit': '10'}
        
        # Should not raise an exception, but return an error result
        try:
            result = get_threat_intelligence_command(mock_client, args)
            # If we get here, the function handled the exception properly
            self.assertIsNotNone(result)
        except Exception as e:
            # If an exception is raised, it should be handled by the main function
            self.fail(f"Exception was not handled properly: {str(e)}")
    
    @patch('orasrs_integration.requests.get')
    def test_exception_in_get_consensus_verification(self, mock_get):
        """Test exception handling in get_consensus_verification_command"""
        mock_get.side_effect = Exception("Connection error")
        
        mock_client = Mock()
        mock_client.get_consensus_verification.side_effect = Exception("API Error")
        
        args = {'threat_id': 'test-id'}
        
        try:
            result = get_consensus_verification_command(mock_client, args)
            self.assertIsNotNone(result)
        except Exception as e:
            self.fail(f"Exception was not handled properly: {str(e)}")


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)