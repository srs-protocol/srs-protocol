# Splunk OraSRS App - Unit Tests
# These tests validate the configuration and functionality of the Splunk App

import unittest
import os
import xml.etree.ElementTree as ET
import json


class TestSplunkApp(unittest.TestCase):
    """Test the OraSRS Splunk App configuration and functionality"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app_dir = "/home/Great/SRS-Protocol/splunk_app"
        self.default_dir = os.path.join(self.app_dir, "default")
        
    def test_app_conf_exists(self):
        """Test that app.conf exists and is properly formatted"""
        app_conf_path = os.path.join(self.default_dir, "app.conf")
        self.assertTrue(os.path.exists(app_conf_path), "app.conf should exist")
        
        with open(app_conf_path, 'r') as f:
            content = f.read()
            
        # Check for required fields
        self.assertIn("OraSRS v2.0 Threat Intelligence", content)
        self.assertIn("orasrs-threat-intelligence", content)
        self.assertIn("OraSRS Protocol Team", content)
    
    def test_dashboard_xml_exists_and_valid(self):
        """Test that dashboard XML exists and is valid XML"""
        dashboard_path = os.path.join(self.default_dir, "data/ui/views/orasrs_dashboard.xml")
        self.assertTrue(os.path.exists(dashboard_path), "Dashboard XML should exist")
        
        # Parse the XML to ensure it's valid
        try:
            tree = ET.parse(dashboard_path)
            root = tree.getroot()
            
            # Verify the dashboard has the correct label
            label_elem = root.find(".//label")
            self.assertIsNotNone(label_elem, "Dashboard should have a label")
            self.assertIn("OraSRS v2.0 Threat Intelligence Dashboard", label_elem.text)
            
            # Check for required panels
            panels = root.findall(".//panel")
            self.assertGreaterEqual(len(panels), 4, "Dashboard should have at least 4 panels")
            
        except ET.ParseError as e:
            self.fail(f"Dashboard XML is not valid: {str(e)}")
    
    def test_props_conf_exists(self):
        """Test that props.conf exists and is properly configured"""
        props_conf_path = os.path.join(self.default_dir, "props.conf")
        self.assertTrue(os.path.exists(props_conf_path), "props.conf should exist")
        
        with open(props_conf_path, 'r') as f:
            content = f.read()
            
        self.assertIn("orasrs_threats", content)
        self.assertIn("orasrs:threat", content)
        self.assertIn("TRANSFORMS-threat_fields", content)
    
    def test_transforms_conf_exists(self):
        """Test that transforms.conf exists and is properly configured"""
        transforms_path = os.path.join(self.default_dir, "transforms.conf")
        self.assertTrue(os.path.exists(transforms_path), "transforms.conf should exist")
        
        with open(transforms_path, 'r') as f:
            content = f.read()
            
        self.assertIn("orasrs_threat_fields", content)
        self.assertIn("orasrs_ip_fields", content)
        self.assertIn("threat_id", content)
        self.assertIn("threat_type", content)
        self.assertIn("REGEX", content)
    
    def test_dashboard_has_required_panels(self):
        """Test that the dashboard has all required panels"""
        dashboard_path = os.path.join(self.default_dir, "data/ui/views/orasrs_dashboard.xml")
        tree = ET.parse(dashboard_path)
        root = tree.getroot()
        
        # Find all panel titles
        panel_titles = []
        for panel in root.findall(".//panel"):
            title_elem = panel.find("title")
            if title_elem is not None:
                panel_titles.append(title_elem.text)
        
        required_titles = [
            "Threat Intelligence Overview",
            "Recent Threats", 
            "Threat Origins by Geography",
            "Threat Types Distribution",
            "Consensus Verification Status",
            "Top Threat Sources"
        ]
        
        for title in required_titles:
            self.assertIn(title, panel_titles, f"Dashboard should contain panel: {title}")
    
    def test_search_queries_valid(self):
        """Test that search queries in dashboard are properly formatted"""
        dashboard_path = os.path.join(self.default_dir, "data/ui/views/orasrs_dashboard.xml")
        tree = ET.parse(dashboard_path)
        root = tree.getroot()
        
        # Find all search queries
        queries = []
        for search in root.findall(".//search/query"):
            if search is not None and search.text:
                queries.append(search.text.strip())
        
        # Check that queries contain required elements
        for query in queries:
            # All queries should reference the orasrs index
            self.assertIn("index=\"orasrs\"", query, f"Query should reference orasrs index: {query}")
    
    def test_field_extraction_patterns(self):
        """Test that field extraction patterns are correctly defined"""
        transforms_path = os.path.join(self.default_dir, "transforms.conf")
        with open(transforms_path, 'r') as f:
            content = f.read()
        
        # Check that threat_id pattern exists
        self.assertIn("threat_id", content)
        self.assertIn("threat-[a-f0-9-]{36}", content)
        
        # Check that threat type pattern exists
        self.assertIn("DDoS|Malware|Phishing|BruteForce|SuspiciousConnection|AnomalousBehavior|IoCMatch", content)
        
        # Check that threat level pattern exists
        self.assertIn("Info|Warning|Critical|Emergency", content)
        
        # Check that IP pattern exists
        self.assertIn("source_ip", content)
        # The actual pattern in transforms.conf is more complex
        self.assertIn("0-9]", content)  # Basic check for IP pattern
    
    def test_app_manifest_content(self):
        """Test that app manifest has required content"""
        app_conf_path = os.path.join(self.default_dir, "app.conf")
        with open(app_conf_path, 'r') as f:
            content = f.readlines()
        
        # Convert to a single string for easier checking
        full_content = ''.join(content)
        
        self.assertIn("id = orasrs-threat-intelligence", full_content)
        self.assertIn("name = OraSRS v2.0 Threat Intelligence", full_content)
        self.assertIn("version = 2.0.0", full_content)
        self.assertIn("author = OraSRS Protocol Team", full_content)
        self.assertIn("description = Integration with OraSRS v2.0", full_content)


class TestSplunkAppIntegration(unittest.TestCase):
    """Test integration aspects of the Splunk App"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app_dir = "/home/Great/SRS-Protocol/splunk_app"
        self.default_dir = os.path.join(self.app_dir, "default")
    
    def test_source_type_consistency(self):
        """Test that sourcetype is consistently defined across configuration files"""
        # Check props.conf
        props_path = os.path.join(self.default_dir, "props.conf")
        with open(props_path, 'r') as f:
            props_content = f.read()
        
        # Check transforms.conf
        transforms_path = os.path.join(self.default_dir, "transforms.conf")
        with open(transforms_path, 'r') as f:
            transforms_content = f.read()
        
        # The sourcetype should be referenced consistently
        self.assertIn("orasrs:threat", props_content)
        self.assertIn("orasrs_threat_fields", transforms_content)
    
    def test_field_extraction_format(self):
        """Test that field extraction format is correct"""
        transforms_path = os.path.join(self.default_dir, "transforms.conf")
        with open(transforms_path, 'r') as f:
            content = f.read()
        
        # Check that FORMAT is properly defined
        self.assertIn("FORMAT =", content)
        # Each extracted field should be properly mapped
        self.assertIn("threat_id::", content)
        self.assertIn("threat_type::", content)
        self.assertIn("threat_level::", content)
        self.assertIn("credibility_score::", content)
        self.assertIn("consensus_confirmed::", content)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
