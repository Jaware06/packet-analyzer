import unittest
import os
import json
from app import app, db, User, Analysis
from detector import ThreatDetector

class PacketAnalyzerTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()

        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_user_registration_and_login(self):
        # 1. Test Registration
        response = self.client.post('/auth/register', data=json.dumps({
            'username': 'testuser',
            'password': 'password123'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('Registration successful', data['message'])

        # 2. Register Duplicate User
        response = self.client.post('/auth/register', data=json.dumps({
            'username': 'testuser',
            'password': 'password123'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 400)

        # 3. Register Short Password
        response = self.client.post('/auth/register', data=json.dumps({
            'username': 'newuser',
            'password': '123'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 400)

        # 4. Login With Bad Credentials
        response = self.client.post('/auth/login', data=json.dumps({
            'username': 'testuser',
            'password': 'wrongpassword'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 401)

        # 5. Login Successfully
        response = self.client.post('/auth/login', data=json.dumps({
            'username': 'testuser',
            'password': 'password123'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['username'], 'testuser')

        # 6. Verify Session State
        response = self.client.get('/auth/session')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['authenticated'])
        self.assertEqual(data['username'], 'testuser')

        # 7. Logout
        response = self.client.post('/auth/logout', headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)

        # 8. Verify Session State After Logout
        response = self.client.get('/auth/session')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertFalse(data['authenticated'])

    def test_authentication_required_routes(self):
        # Test that dashboard and other endpoints block anonymous access
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)  # Redirects to login

        response = self.client.post('/live/start')
        self.assertEqual(response.status_code, 302)

        response = self.client.get('/history')
        self.assertEqual(response.status_code, 302)

    def test_dynamic_threat_detector_scoring(self):
        detector = ThreatDetector()

        # 1. Test clean traffic
        clean_packets = [
            {'src': '192.168.1.10', 'dst': '192.168.1.1', 'protocol': 'TCP', 'info': 'Port: 50400->443'},
            {'src': '192.168.1.1', 'dst': '192.168.1.10', 'protocol': 'TCP', 'info': 'Port: 443->50400'},
            {'src': '192.168.1.15', 'dst': '8.8.8.8', 'protocol': 'UDP', 'info': 'Port: 49000->53 | Domain: example.com | DNS Query'},
        ]
        threats = detector.analyze(clean_packets)
        # Clean packets shouldn't trigger critical/high volume alerts
        high_severity_threats = [t for t in threats if t['severity'] in ('Critical', 'High')]
        self.assertEqual(len(high_severity_threats), 0)

        # 2. Test Port Scan detection
        scan_packets = []
        for dport in range(10, 35):
            scan_packets.append({
                'src': '10.0.0.99', 
                'dst': '192.168.1.1', 
                'protocol': 'TCP', 
                'info': f'Port: 12345->{dport}'
            })
        threats = detector.analyze(scan_packets)
        scan_alerts = [t for t in threats if 'port scan' in t['details'].lower()]
        self.assertTrue(len(scan_alerts) > 0)
        self.assertEqual(scan_alerts[0]['source'], '10.0.0.99')

        # 3. Test Brute Force detection
        bf_packets = []
        for _ in range(25):
            bf_packets.append({
                'src': '10.0.0.99', 
                'dst': '192.168.1.5', 
                'protocol': 'TCP', 
                'info': 'Port: 55443->22'  # Target SSH
            })
        threats = detector.analyze(bf_packets)
        bf_alerts = [t for t in threats if 'brute force' in t['details'].lower() or 'sensitive admin ports' in t['details'].lower()]
        self.assertTrue(len(bf_alerts) > 0)

        # 4. Test DDoS detection (anomalous traffic volume)
        ddos_packets = []
        # Add normal baseline first so std_dev calculation has context
        for i in range(10):
            ddos_packets.append({'src': f'192.168.1.{i+10}', 'dst': '8.8.8.8', 'protocol': 'TCP', 'info': 'Port: 1234->80'})
        # Add DDoS flooding packets from a single source
        for _ in range(180):
            ddos_packets.append({'src': '10.0.0.50', 'dst': '8.8.8.8', 'protocol': 'UDP', 'info': 'Port: 32201->53'})
        
        threats = detector.analyze(ddos_packets)
        ddos_alerts = [t for t in threats if 'high packet volume' in t['details'].lower() or 'statistically anomalous' in t['details'].lower()]
        self.assertTrue(len(ddos_alerts) > 0)
        self.assertEqual(ddos_alerts[0]['source'], '10.0.0.50')

        # 5. Test ARP Spoofing detection
        arp_packets = [
            {'protocol': 'ARP', 'info': 'ARP: is-at 192.168.1.1 -> 192.168.1.15 MAC: 00:11:22:33:44:55'},
            {'protocol': 'ARP', 'info': 'ARP: is-at 192.168.1.1 -> 192.168.1.20 MAC: aa:bb:cc:dd:ee:ff'}
        ]
        threats = detector.analyze(arp_packets)
        arp_alerts = [t for t in threats if t['type'] == 'ARP Spoofing Detected']
        self.assertTrue(len(arp_alerts) > 0)
        self.assertEqual(arp_alerts[0]['source'], '192.168.1.1')

if __name__ == '__main__':
    unittest.main()
