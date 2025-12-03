"""OraSRS v2.0 Threat Intelligence Integration for XSOAR

This integration connects to the OraSRS v2.0 decentralized threat intelligence network,
providing real-time threat data and consensus-verified intelligence.
"""

from typing import Any, Dict, List, Optional
import requests
import urllib3
from datetime import datetime
import json

import demistomock as demisto  # noqa: F401 pylint: disable=import-error
from CommonServerPython import *  # noqa: F401 pylint: disable=import-error
from CommonServerUserPython import *  # noqa: F401 pylint: disable=import-error


# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Client(BaseClient):
    """Client class to interact with OraSRS v2.0 API"""

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        super().__init__(base_url=base_url, verify=verify_ssl)
        self._headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

    def test_connection(self) -> Dict[str, Any]:
        """Test the connection to OraSRS API"""
        return self._http_request(
            method='GET',
            url_suffix='/api/v2.0/health',
            headers=self._headers
        )

    def get_threat_intelligence(self, threat_id: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """Get threat intelligence from OraSRS network"""
        params = {'limit': limit}
        if threat_id:
            params['threat_id'] = threat_id

        return self._http_request(
            method='GET',
            url_suffix='/api/v2.0/threats',
            headers=self._headers,
            params=params
        )

    def get_consensus_verification(self, threat_id: str) -> Dict[str, Any]:
        """Get consensus verification status for a threat"""
        return self._http_request(
            method='GET',
            url_suffix=f'/api/v2.0/threats/{threat_id}/consensus',
            headers=self._headers
        )

    def submit_threat_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Submit threat evidence to OraSRS network"""
        return self._http_request(
            method='POST',
            url_suffix='/api/v2.0/threats',
            headers=self._headers,
            json_data=evidence
        )

    def get_upstream_intelligence(self) -> Dict[str, Any]:
        """Get upstream threat intelligence (e.g., from CISA AIS)"""
        return self._http_request(
            method='GET',
            url_suffix='/api/v2.0/threats/upstream',
            headers=self._headers
        )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication."""
    try:
        response = client.test_connection()
        if response.get('status') == 'healthy':
            return 'ok'
        else:
            return f'API connection failed: {response}'
    except Exception as e:
        return str(e)


def get_threat_intelligence_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get threat intelligence from OraSRS network"""
    threat_id = args.get('threat_id')
    limit = int(args.get('limit', 50))

    response = client.get_threat_intelligence(threat_id=threat_id, limit=limit)

    # Prepare outputs
    outputs = []
    for threat in response.get('threats', []):
        output = {
            'ID': threat.get('id'),
            'ThreatType': threat.get('threat_type'),
            'ThreatLevel': threat.get('threat_level'),
            'SourceIP': threat.get('source_ip'),
            'TargetIP': threat.get('target_ip'),
            'Timestamp': threat.get('timestamp'),
            'CredibilityScore': threat.get('credibility_score', 0.0),
            'ConsensusVerified': threat.get('consensus_verified', False),
            'Context': threat.get('context'),
            'EvidenceHash': threat.get('evidence_hash')
        }
        outputs.append(output)

    readable_output = tableToMarkdown(
        f"OraSRS Threat Intelligence ({len(outputs)} threats found)",
        outputs,
        headers=['ID', 'ThreatType', 'ThreatLevel', 'SourceIP', 'CredibilityScore', 'ConsensusVerified', 'Context']
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OraSRS.Threat',
        outputs_key_field='ID',
        outputs=outputs
    )


def get_consensus_verification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get consensus verification status for a specific threat"""
    threat_id = args['threat_id']

    response = client.get_consensus_verification(threat_id)

    output = {
        'ThreatID': threat_id,
        'ConsensusStatus': response.get('consensus_status'),
        'ConfidenceScore': response.get('confidence_score', 0.0),
        'TotalVerifiers': response.get('total_verifiers', 0),
        'ConsensusPercentage': response.get('consensus_percentage', 0.0),
        'VerifiedBy': response.get('verified_by', []),
        'DisputedBy': response.get('disputed_by', [])
    }

    readable_output = tableToMarkdown(
        f"OraSRS Consensus Verification for Threat {threat_id}",
        output,
        headers=['ThreatID', 'ConsensusStatus', 'ConfidenceScore', 'TotalVerifiers', 'ConsensusPercentage']
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OraSRS.Consensus',
        outputs_key_field='ThreatID',
        outputs=output
    )


def submit_threat_evidence_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Submit threat evidence to OraSRS network"""
    evidence = {
        'source_ip': args['source_ip'],
        'target_ip': args.get('target_ip'),
        'threat_type': args['threat_type'],
        'threat_level': args.get('threat_level', 'Warning'),
        'context': args['context'],
        'network_flow': args.get('network_flow', ''),
        'geolocation': args.get('geolocation', 'unknown'),
        'agent_id': args.get('agent_id', 'xsoar-integration')
    }

    response = client.submit_threat_evidence(evidence)

    output = {
        'SubmittedThreatID': response.get('id'),
        'Status': response.get('status'),
        'Message': response.get('message', 'Threat evidence submitted successfully')
    }

    readable_output = tableToMarkdown(
        "OraSRS Threat Evidence Submission",
        output,
        headers=['SubmittedThreatID', 'Status', 'Message']
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OraSRS.Submission',
        outputs_key_field='SubmittedThreatID',
        outputs=output
    )


def get_upstream_intelligence_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get upstream threat intelligence (e.g., from CISA AIS)"""
    response = client.get_upstream_intelligence()

    outputs = []
    for threat in response.get('upstream_threats', []):
        output = {
            'ID': threat.get('id'),
            'SourceType': threat.get('source_type', 'upstream'),
            'ThreatType': threat.get('threat_type'),
            'ThreatLevel': threat.get('threat_level'),
            'SourceIP': threat.get('source_ip'),
            'Timestamp': threat.get('timestamp'),
            'ConfidenceScore': threat.get('confidence', 0.0),
            'Description': threat.get('description', ''),
            'Source': threat.get('source', 'upstream_feed')
        }
        outputs.append(output)

    readable_output = tableToMarkdown(
        f"OraSRS Upstream Threat Intelligence ({len(outputs)} threats found)",
        outputs,
        headers=['ID', 'SourceType', 'ThreatType', 'ThreatLevel', 'SourceIP', 'ConfidenceScore', 'Description']
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OraSRS.UpstreamThreat',
        outputs_key_field='ID',
        outputs=outputs
    )


def main():
    """Main function to handle XSOAR integration commands"""
    params = demisto.params()
    base_url = params.get('url', '').rstrip('/')
    api_key = params.get('api_key', '')
    verify_ssl = not params.get('insecure', False)

    command = demisto.command()
    args = demisto.args()

    client = Client(base_url=base_url, api_key=api_key, verify_ssl=verify_ssl)

    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'orasrs-get-threat-intelligence':
            return_results(get_threat_intelligence_command(client, args))
        elif command == 'orasrs-get-consensus-verification':
            return_results(get_consensus_verification_command(client, args))
        elif command == 'orasrs-submit-threat-evidence':
            return_results(submit_threat_evidence_command(client, args))
        elif command == 'orasrs-get-upstream-intelligence':
            return_results(get_upstream_intelligence_command(client, args))
    except Exception as e:
        demisto.error(f"Error in OraSRS integration: {str(e)}")
        return_results(CommandResults(
            readable_output=f"Error in OraSRS integration: {str(e)}",
            outputs_prefix='OraSRS.Error',
            outputs={'ErrorMessage': str(e)}
        ))


if __name__ in ('__main__', 'builtins'):
    main()